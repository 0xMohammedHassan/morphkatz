#include "morphkatz/rules/rule_loader.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/ir/flags_effect.hpp"

#include <Zydis/Zydis.h>
#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace morphkatz::rules {

namespace {

std::string to_upper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return s;
}

ir::MnemonicId mnemonic_from_name(const std::string& raw) {
    const auto up = to_upper(raw);
    for (ZyanU32 i = 1; i < ZYDIS_MNEMONIC_MAX_VALUE; ++i) {
        const char* name = ZydisMnemonicGetString(static_cast<ZydisMnemonic>(i));
        if (!name) continue;
        std::string u(name);
        std::transform(u.begin(), u.end(), u.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        if (u == up) return static_cast<ir::MnemonicId>(i);
    }
    return 0;
}

ir::RegisterId register_from_name(const std::string& raw) {
    const auto up = to_upper(raw);
    for (ZyanU32 i = 1; i < ZYDIS_REGISTER_MAX_VALUE; ++i) {
        const char* name = ZydisRegisterGetString(static_cast<ZydisRegister>(i));
        if (!name) continue;
        std::string u(name);
        std::transform(u.begin(), u.end(), u.begin(),
                       [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
        if (u == up) return static_cast<ir::RegisterId>(i);
    }
    return 0;
}

OperandKindMatch parse_kind(const std::string& raw) {
    const auto up = to_upper(raw);
    if (up == "REGISTER")  return OperandKindMatch::Register;
    if (up == "IMMEDIATE") return OperandKindMatch::Immediate;
    if (up == "MEMORY")    return OperandKindMatch::Memory;
    if (up == "RELATIVE")  return OperandKindMatch::Relative;
    return OperandKindMatch::Any;
}

RegisterClass parse_class(const std::string& raw) {
    const auto up = to_upper(raw);
    if (up == "GPR")   return RegisterClass::Gpr;
    if (up == "GPR8")  return RegisterClass::Gpr8;
    if (up == "GPR16") return RegisterClass::Gpr16;
    if (up == "GPR32") return RegisterClass::Gpr32;
    if (up == "GPR64") return RegisterClass::Gpr64;
    if (up == "XMM")   return RegisterClass::Xmm;
    if (up == "YMM")   return RegisterClass::Ymm;
    if (up == "ZMM")   return RegisterClass::Zmm;
    return RegisterClass::Any;
}

FlagsEquivalence parse_flags_effect(const std::string& raw) {
    if (raw.rfind("equivalent_if", 0) == 0) return FlagsEquivalence::EquivalentIfDead;
    if (raw == "equivalent")                return FlagsEquivalence::Equivalent;
    return FlagsEquivalence::NotVerified;
}

uint32_t parse_flag_name(const std::string& raw) {
    auto u = to_upper(raw);
    if (u == "CF") return ir::F_CF;
    if (u == "PF") return ir::F_PF;
    if (u == "AF") return ir::F_AF;
    if (u == "ZF") return ir::F_ZF;
    if (u == "SF") return ir::F_SF;
    if (u == "TF") return ir::F_TF;
    if (u == "IF") return ir::F_IF;
    if (u == "DF") return ir::F_DF;
    if (u == "OF") return ir::F_OF;
    return 0;
}

std::vector<uint8_t> parse_hex_bytes(const std::string& raw) {
    std::vector<uint8_t> out;
    out.reserve(raw.size() / 2);
    unsigned nyb = 0;
    bool have   = false;
    for (char c : raw) {
        if (c == ' ' || c == '\t' || c == ',' || c == ':' || c == '\n') continue;
        unsigned v = 0;
        if (c >= '0' && c <= '9')      v = static_cast<unsigned>(c - '0');
        else if (c >= 'a' && c <= 'f') v = static_cast<unsigned>(10 + (c - 'a'));
        else if (c >= 'A' && c <= 'F') v = static_cast<unsigned>(10 + (c - 'A'));
        else continue;
        if (!have) { nyb = v << 4; have = true; }
        else       { out.push_back(static_cast<uint8_t>(nyb | v)); have = false; }
    }
    return out;
}

bool register_in_class(ir::RegisterId r, RegisterClass c) {
    if (r == 0 || c == RegisterClass::Any) return c == RegisterClass::Any;
    const auto zc = ZydisRegisterGetClass(static_cast<ZydisRegister>(r));
    switch (c) {
        case RegisterClass::Gpr:    return zc >= ZYDIS_REGCLASS_GPR8 && zc <= ZYDIS_REGCLASS_GPR64;
        case RegisterClass::Gpr8:   return zc == ZYDIS_REGCLASS_GPR8;
        case RegisterClass::Gpr16:  return zc == ZYDIS_REGCLASS_GPR16;
        case RegisterClass::Gpr32:  return zc == ZYDIS_REGCLASS_GPR32;
        case RegisterClass::Gpr64:  return zc == ZYDIS_REGCLASS_GPR64;
        case RegisterClass::Xmm:    return zc == ZYDIS_REGCLASS_XMM;
        case RegisterClass::Ymm:    return zc == ZYDIS_REGCLASS_YMM;
        case RegisterClass::Zmm:    return zc == ZYDIS_REGCLASS_ZMM;
        case RegisterClass::Any:    return true;
    }
    return false;
}

void compile_predicate(Rule& r) {
    // Capture by value so the closure doesn't dangle.
    const auto mnem         = r.match_mnemonic;
    const auto op_cnt       = r.match_operand_count;
    const auto constraints  = r.constraints;
    const auto same_regs    = r.same_register;
    const auto blacklist    = r.register_blacklist;

    r.compiled_predicate = [mnem, op_cnt, constraints, same_regs, blacklist](
                               const ir::Instruction& ins) -> bool {
        if (mnem && ins.mnemonic != mnem) return false;
        if (op_cnt >= 0 && ins.op_count != static_cast<uint8_t>(op_cnt)) return false;

        for (const auto& c : constraints) {
            if (c.op_index >= ins.op_count) return false;
            const auto& op = ins.ops[c.op_index];
            if (c.kind != OperandKindMatch::Any) {
                const bool kind_ok =
                    (c.kind == OperandKindMatch::Register  && op.kind == ir::Operand::Kind::Register)  ||
                    (c.kind == OperandKindMatch::Immediate && op.kind == ir::Operand::Kind::Immediate) ||
                    (c.kind == OperandKindMatch::Memory    && op.kind == ir::Operand::Kind::Memory)    ||
                    (c.kind == OperandKindMatch::Relative  && op.kind == ir::Operand::Kind::Relative);
                if (!kind_ok) return false;
            }
            if (c.reg_class != RegisterClass::Any) {
                if (op.kind != ir::Operand::Kind::Register) return false;
                if (!register_in_class(op.reg, c.reg_class)) return false;
            }
            if (c.imm_equals.has_value()) {
                if (op.kind != ir::Operand::Kind::Immediate) return false;
                if (op.imm != *c.imm_equals) return false;
            }
            if (c.size_bits != 0 && op.size_bits != c.size_bits) return false;
        }

        for (const auto& s : same_regs) {
            if (!ins.same_register(s.op_a, s.op_b)) return false;
        }

        if (!blacklist.empty()) {
            for (uint8_t i = 0; i < ins.op_count; ++i) {
                const auto& op = ins.ops[i];
                if (op.kind != ir::Operand::Kind::Register) continue;
                for (auto banned : blacklist) {
                    if (op.reg == banned) return false;
                    // Also reject sub-registers of banned parents (e.g. ESP/SP/SPL for RSP).
                    const auto op_reg = static_cast<ZydisRegister>(op.reg);
                    const auto ban_reg = static_cast<ZydisRegister>(banned);
                    const auto zc     = ZydisRegisterGetClass(op_reg);
                    const auto id     = ZydisRegisterGetId(op_reg);
                    const auto bid    = ZydisRegisterGetId(ban_reg);
                    if (zc >= ZYDIS_REGCLASS_GPR8 && zc <= ZYDIS_REGCLASS_GPR64 && id == bid) {
                        return false;
                    }
                }
            }
        }
        return true;
    };
}

Result<Rule> parse_one(const YAML::Node& node, const std::filesystem::path& src) {
    Rule r;
    r.source_file = src.string();
    if (node["id"])          r.id          = node["id"].as<std::string>();
    if (node["description"]) r.description = node["description"].as<std::string>();

    if (const auto m = node["match"]) {
        if (m["mnemonic"]) {
            r.match_mnemonic_name = m["mnemonic"].as<std::string>();
            r.match_mnemonic      = mnemonic_from_name(r.match_mnemonic_name);
            if (!r.match_mnemonic) {
                return Error::make(ErrorKind::RuleLoad,
                    "unknown mnemonic: " + r.match_mnemonic_name, r.id);
            }
        }
        if (m["operand_count"]) {
            r.match_operand_count = m["operand_count"].as<int>();
        }
        if (const auto cs = m["constraints"]) {
            for (const auto& c : cs) {
                if (c["same_register"]) {
                    auto pair = c["same_register"].as<std::vector<unsigned>>();
                    if (pair.size() == 2) r.same_register.push_back({pair[0], pair[1]});
                    continue;
                }
                if (c["register_blacklist"]) {
                    for (const auto& name : c["register_blacklist"]) {
                        auto reg = register_from_name(name.as<std::string>());
                        if (reg) r.register_blacklist.push_back(reg);
                    }
                    continue;
                }
                OperandConstraint oc;
                if (c["op"])       oc.op_index  = c["op"].as<unsigned>();
                if (c["kind"])     oc.kind      = parse_kind(c["kind"].as<std::string>());
                if (c["class"])    oc.reg_class = parse_class(c["class"].as<std::string>());
                if (c["size_bits"])oc.size_bits = c["size_bits"].as<uint16_t>();
                if (c["imm"])      oc.imm_equals = c["imm"].as<int64_t>();
                r.constraints.push_back(oc);
            }
        }
    }

    if (const auto raw = node["raw"]) {
        if (raw["from"]) r.raw_from = parse_hex_bytes(raw["from"].as<std::string>());
        if (raw["to"])   r.raw_to   = parse_hex_bytes(raw["to"].as<std::string>());
    }

    if (const auto rw = node["rewrite"]) {
        if (rw["mnemonic"]) {
            r.rewrite_mnemonic_name = rw["mnemonic"].as<std::string>();
            r.rewrite_mnemonic      = mnemonic_from_name(r.rewrite_mnemonic_name);
        }
        if (const auto ops = rw["operands"]) {
            for (const auto& op : ops) {
                Rule::RewriteOperand ro;
                if (op["copy_from"]) {
                    ro.source       = Rule::RewriteOperand::Source::CopyFrom;
                    ro.copy_from_op = op["copy_from"].as<unsigned>();
                    // Optional `transform: negate` flips the sign of the
                    // copied immediate. Required for the SUB <-> ADD
                    // swap rules: `sub a, X` ≡ `add a, -X`, not
                    // `add a, X` (which is what a verbatim copy gives).
                    if (op["transform"]) {
                        const auto t = op["transform"].as<std::string>();
                        if (t == "negate") {
                            ro.imm_transform =
                                Rule::RewriteOperand::ImmTransform::Negate;
                        }
                    }
                } else if (op["kind"] && op["kind"].as<std::string>() == "immediate") {
                    ro.source        = Rule::RewriteOperand::Source::Immediate;
                    ro.imm_value     = op["value"].as<int64_t>(0);
                    ro.imm_size_bits = op["size_bits"].as<uint16_t>(32);
                } else if (op["kind"] && op["kind"].as<std::string>() == "register") {
                    ro.source   = Rule::RewriteOperand::Source::Register;
                    ro.reg      = register_from_name(op["name"].as<std::string>());
                    ro.size_bits= op["size_bits"].as<uint16_t>(64);
                }
                r.rewrite_operands.push_back(ro);
            }
        }
    }

    if (node["flags_effect"])
        r.flags_effect = parse_flags_effect(node["flags_effect"].as<std::string>());
    if (const auto fv = node["flags_value_differs_in"]) {
        // Accept either a YAML list or a "|"-separated string. Authors
        // typically use the list form; the string form falls out of the
        // existing flags_to_string formatter so reports round-trip.
        uint32_t mask = 0;
        if (fv.IsSequence()) {
            for (const auto& f : fv) mask |= parse_flag_name(f.as<std::string>());
        } else if (fv.IsScalar()) {
            std::string raw = fv.as<std::string>();
            std::string token;
            for (char c : raw) {
                if (c == '|' || c == ',' || std::isspace(static_cast<unsigned char>(c))) {
                    if (!token.empty()) { mask |= parse_flag_name(token); token.clear(); }
                } else {
                    token.push_back(c);
                }
            }
            if (!token.empty()) mask |= parse_flag_name(token);
        }
        r.flags_value_diff_mask = mask;
    }
    if (node["size_delta"])
        r.size_delta   = node["size_delta"].as<int32_t>();
    if (node["weight"])
        r.weight       = node["weight"].as<double>();

    compile_predicate(r);
    return r;
}

}  // namespace

RulePack::RulePack(std::vector<Rule> rules, std::vector<std::string> packs)
    : rules_(std::move(rules)), packs_(std::move(packs)) {}

Result<std::vector<Rule>> load_file(const std::filesystem::path& yaml_path) {
    std::ifstream f(yaml_path);
    if (!f) return Error::make(ErrorKind::Io, "cannot open rule file", yaml_path.string());

    YAML::Node doc;
    try {
        doc = YAML::Load(f);
    } catch (const std::exception& e) {
        return Error::make(ErrorKind::RuleLoad, e.what(), yaml_path.string());
    }

    std::vector<Rule> out;
    const auto array = doc["rules"] ? doc["rules"] : doc;
    if (!array.IsSequence()) {
        return Error::make(ErrorKind::RuleLoad, "top-level 'rules' must be a sequence",
                           yaml_path.string());
    }

    for (const auto& node : array) {
        auto r = parse_one(node, yaml_path);
        if (!r.ok()) return r.error();
        out.push_back(std::move(*r));
    }
    return out;
}

Result<std::unique_ptr<RulePack>> load_all(const LoaderOptions& opts) {
    std::vector<Rule> rules;
    std::vector<std::string> packs;

    auto load_dir = [&](const std::filesystem::path& dir) -> Result<void> {
        if (dir.empty() || !std::filesystem::is_directory(dir)) return {};
        for (auto& e : std::filesystem::recursive_directory_iterator(dir)) {
            if (!e.is_regular_file()) continue;
            const auto ext = e.path().extension().string();
            if (ext != ".yaml" && ext != ".yml") continue;
            auto one = load_file(e.path());
            if (!one.ok()) return one.error();
            rules.insert(rules.end(),
                         std::make_move_iterator(one->begin()),
                         std::make_move_iterator(one->end()));
            packs.push_back(e.path().filename().string());
        }
        return {};
    };

    if (auto r = load_dir(opts.default_rules_dir); !r.ok()) return r.error();
    for (const auto& extra : opts.extra_paths) {
        if (std::filesystem::is_directory(extra)) {
            if (auto r = load_dir(extra); !r.ok()) return r.error();
        } else {
            auto one = load_file(extra);
            if (!one.ok()) return one.error();
            rules.insert(rules.end(),
                         std::make_move_iterator(one->begin()),
                         std::make_move_iterator(one->end()));
            packs.push_back(extra.filename().string());
        }
    }

    MK_DEBUG("Rule loader parsed {} rules from {} files", rules.size(), packs.size());
    return std::make_unique<RulePack>(std::move(rules), std::move(packs));
}

}
