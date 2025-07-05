package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** This structure is used for a hash signing object. */
public class TPMT_KEYEDHASH_SCHEME extends TpmStructure
{
    /** Selects the scheme */
    public TPM_ALG_ID scheme() { return details != null ? details.GetUnionSelector() : TPM_ALG_ID.NULL; }

    /** The scheme parameters
     *  One of: TPMS_SCHEME_HMAC, TPMS_SCHEME_XOR, TPMS_NULL_SCHEME_KEYEDHASH.
     */
    public TPMU_SCHEME_KEYEDHASH details;

    public TPMT_KEYEDHASH_SCHEME() {}

    /** @param _details The scheme parameters
     *         One of: TPMS_SCHEME_HMAC, TPMS_SCHEME_XOR, TPMS_NULL_SCHEME_KEYEDHASH.
     */
    public TPMT_KEYEDHASH_SCHEME(TPMU_SCHEME_KEYEDHASH _details) { details = _details; }

    /** TpmMarshaller method */
    @Override
    public void toTpm(TpmBuffer buf)
    {
        if (details == null) return;
        buf.writeShort(details.GetUnionSelector());
        details.toTpm(buf);
    }

    /** TpmMarshaller method */
    @Override
    public void initFromTpm(TpmBuffer buf)
    {
        TPM_ALG_ID scheme = TPM_ALG_ID.fromTpm(buf);
        details = UnionFactory.create("TPMU_SCHEME_KEYEDHASH", scheme);
        details.initFromTpm(buf);
    }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMT_KEYEDHASH_SCHEME fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(TPMT_KEYEDHASH_SCHEME.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMT_KEYEDHASH_SCHEME fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMT_KEYEDHASH_SCHEME fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(TPMT_KEYEDHASH_SCHEME.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("TPMT_KEYEDHASH_SCHEME");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }

    @Override
    public void toStringInternal(TpmStructurePrinter _p, int d)
    {
        _p.add(d, "TPMU_SCHEME_KEYEDHASH", "details", details);
    }
}

//<<<
