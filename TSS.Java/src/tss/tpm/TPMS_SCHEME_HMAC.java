package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** Table 155 Definition of Types for HMAC_SIG_SCHEME */
public class TPMS_SCHEME_HMAC extends TPMS_SCHEME_HASH
{
    public TPMS_SCHEME_HMAC() {}

    /** @param _hashAlg The hash algorithm used to digest the message */
    public TPMS_SCHEME_HMAC(TPM_ALG_ID _hashAlg) { super(_hashAlg); }

    /** TpmUnion method */
    public TPM_ALG_ID GetUnionSelector() { return TPM_ALG_ID.HMAC; }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMS_SCHEME_HMAC fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(TPMS_SCHEME_HMAC.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMS_SCHEME_HMAC fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMS_SCHEME_HMAC fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(TPMS_SCHEME_HMAC.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("TPMS_SCHEME_HMAC");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }
}

//<<<
