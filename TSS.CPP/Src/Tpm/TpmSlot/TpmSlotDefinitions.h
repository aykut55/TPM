#pragma once

enum class Endianness
{
    LittleEndian,
    BigEndian
};

enum class SlotType : uint32_t
{
    Unknown = 0,
    Int = 0x494E5430,  // "INT0"
    Float = 0x464C5430,  // "FLT0"
    Double = 0x44424C30,  // "DBL0"
    String = 0x53545230,  // "STR0"
    Byte = 0x42495430,  // "BIT0"
    Char = 0x43484130,   // "CHA0"

    IntArray = 0x494E5441, // "INTA"
    FloatArray = 0x464C5441, // "FLTA"
    DoubleArray = 0x44424C41, // "DBLA"
    StringArray = 0x53545241, // "STRA"
    ByteArray = 0x42595441, // "BYTEA"
    CharArray = 0x43484141  // "CHARA"
};

struct SlotInfo
{
    UINT32 slotNo;
    bool   isDefined;
    SlotType type;
};