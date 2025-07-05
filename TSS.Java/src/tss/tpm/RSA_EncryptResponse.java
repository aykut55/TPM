package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** This command performs RSA encryption using the indicated padding scheme according to
 *  IETF RFC 8017. If the scheme of keyHandle is TPM_ALG_NULL, then the caller may use
 *  inScheme to specify the padding scheme. If scheme of keyHandle is not TPM_ALG_NULL,
 *  then inScheme shall either be TPM_ALG_NULL or be the same as scheme (TPM_RC_SCHEME).
 */
public class RSA_EncryptResponse extends RespStructure
{
    /** Encrypted output */
    public byte[] outData;

    public RSA_EncryptResponse() {}

    /** TpmMarshaller method */
    @Override
    public void toTpm(TpmBuffer buf) { buf.writeSizedByteBuf(outData); }

    /** TpmMarshaller method */
    @Override
    public void initFromTpm(TpmBuffer buf) { outData = buf.readSizedByteBuf(); }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static RSA_EncryptResponse fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(RSA_EncryptResponse.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static RSA_EncryptResponse fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static RSA_EncryptResponse fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(RSA_EncryptResponse.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("RSA_EncryptResponse");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }

    @Override
    public void toStringInternal(TpmStructurePrinter _p, int d)
    {
        _p.add(d, "byte[]", "outData", outData);
    }

    @Override
    public SessEncInfo sessEncInfo() { return new SessEncInfo(2, 1); }
}

//<<<
