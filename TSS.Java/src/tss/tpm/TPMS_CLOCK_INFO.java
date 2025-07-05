package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** This structure is used in each of the attestation commands. */
public class TPMS_CLOCK_INFO extends TpmStructure
{
    /** Time value in milliseconds that advances while the TPM is powered
     *  NOTE The interpretation of the time-origin (clock=0) is out of the scope of this
     *  specification, although Coordinated Universal Time (UTC) is expected to be a common
     *  convention. This structure element is used to report on the TPM's Clock value.
     *  This value is reset to zero when the Storage Primary Seed is changed (TPM2_Clear()).
     *  This value may be advanced by TPM2_ClockSet().
     */
    public long clock;

    /** Number of occurrences of TPM Reset since the last TPM2_Clear() */
    public int resetCount;

    /** Number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since the last
     *  TPM Reset or TPM2_Clear().
     */
    public int restartCount;

    /** No value of Clock greater than the current value of Clock has been previously reported
     *  by the TPM. Set to YES on TPM2_Clear().
     */
    public byte safe;

    public TPMS_CLOCK_INFO() {}

    /** @param _clock Time value in milliseconds that advances while the TPM is powered
     *         NOTE The interpretation of the time-origin (clock=0) is out of the scope of this
     *         specification, although Coordinated Universal Time (UTC) is expected to be a common
     *         convention. This structure element is used to report on the TPM's Clock value.
     *         This value is reset to zero when the Storage Primary Seed is changed (TPM2_Clear()).
     *         This value may be advanced by TPM2_ClockSet().
     *  @param _resetCount Number of occurrences of TPM Reset since the last TPM2_Clear()
     *  @param _restartCount Number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred
     *         since the last TPM Reset or TPM2_Clear().
     *  @param _safe No value of Clock greater than the current value of Clock has been previously
     *         reported by the TPM. Set to YES on TPM2_Clear().
     */
    public TPMS_CLOCK_INFO(long _clock, int _resetCount, int _restartCount, byte _safe)
    {
        clock = _clock;
        resetCount = _resetCount;
        restartCount = _restartCount;
        safe = _safe;
    }

    /** TpmMarshaller method */
    @Override
    public void toTpm(TpmBuffer buf)
    {
        buf.writeInt64(clock);
        buf.writeInt(resetCount);
        buf.writeInt(restartCount);
        buf.writeByte(safe);
    }

    /** TpmMarshaller method */
    @Override
    public void initFromTpm(TpmBuffer buf)
    {
        clock = buf.readInt64();
        resetCount = buf.readInt();
        restartCount = buf.readInt();
        safe = buf.readByte();
    }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMS_CLOCK_INFO fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(TPMS_CLOCK_INFO.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMS_CLOCK_INFO fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMS_CLOCK_INFO fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(TPMS_CLOCK_INFO.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("TPMS_CLOCK_INFO");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }

    @Override
    public void toStringInternal(TpmStructurePrinter _p, int d)
    {
        _p.add(d, "long", "clock", clock);
        _p.add(d, "int", "resetCount", resetCount);
        _p.add(d, "int", "restartCount", restartCount);
        _p.add(d, "byte", "safe", safe);
    }
}

//<<<
