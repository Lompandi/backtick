
#include "globals.hpp"

EXT_API_VERSION g_ExtApiVersion = { 1,1,EXT_API_VERSION_NUMBER, 0 };
// 
WINDBG_EXTENSION_APIS ExtensionApis = { 0 };

bool InShadowState = false;

std::string REGVAL::ToString() const {

    switch (Type) {
    case REGVAL_TYPE_I32:
        return std::format("{}", u.I32);
    case REGVAL_TYPE_I64:
        return std::format("{}", u.I64);
    case REGVAL_TYPE_FLOAT80: {

    }
    case REGVAL_TYPE_VF128: {
        std::string Fmt;
        for (int i = 0; i < 4; i++) {
            Fmt += std::format("{} ", u.VF128.f[i]);
        }
        Fmt.pop_back();
        return Fmt;
    }
    case REGVAL_TYPE_VF256: {
        std::string Fmt;
        for (int i = 0; i < 8; i++) {
            Fmt += std::format("{} ", u.VF256.f[i]);
        }
        Fmt.pop_back();
        return Fmt;
    }
    case REGVAL_TYPE_VF512: {
        std::string Fmt;
        for (int i = 0; i < 16; i++) {
            Fmt += std::format("{} ", u.VF512.f[i]);
        }
        Fmt.pop_back();
        return Fmt;
    }
    default:
        return "<invalid>";
    }
}