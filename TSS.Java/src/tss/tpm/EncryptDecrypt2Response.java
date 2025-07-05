package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** This command is identical to TPM2_EncryptDecrypt(), except that the inData parameter
 *  is the first parameter. This permits inData to be parameter encrypted.
 */
public class EncryptDecrypt2Response extends RespStructure
{
    /** Encrypted or decrypted output */
    public byte[] outData;

    /** Chaining value to use for IV in next round */
    public byte[] ivOut;

    public EncryptDecrypt2Response() {}

    /** TpmMarshaller method */
    @Override
    public void toTpm(TpmBuffer buf)
    {
        buf.writeSizedByteBuf(outData);
        buf.writeSizedByteBuf(ivOut);
    }

    /** TpmMarshaller method */
    @Override
    public void initFromTpm(TpmBuffer buf)
    {
        outData = buf.readSizedByteBuf();
        ivOut = buf.readSizedByteBuf();
    }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static EncryptDecrypt2Response fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(EncryptDecrypt2Response.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static EncryptDecrypt2Response fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static EncryptDecrypt2Response fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(EncryptDecrypt2Response.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("EncryptDecrypt2Response");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }

    @Override
    public void toStringInternal(TpmStructurePrinter _p, int d)
    {
        _p.add(d, "byte[]", "outData", outData);
        _p.add(d, "byte[]", "ivOut", ivOut);
    }

    @Override
    public SessEncInfo sessEncInfo() { return new SessEncInfo(2, 1); }
}

//<<<
