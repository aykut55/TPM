package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** This buffer holds a label or context value. For interoperability and backwards
 *  compatibility, LABEL_MAX_BUFFER is the minimum of the largest digest on the device and
 *  the largest ECC parameter (MAX_ECC_KEY_BYTES) but no more than 32 bytes.
 */
public class TPM2B_LABEL extends TpmStructure
{
    /** Symmetric data for a created object or the label and context for a derived object */
    public byte[] buffer;

    public TPM2B_LABEL() {}

    /** @param _buffer Symmetric data for a created object or the label and context for a
     *  derived object
     */
    public TPM2B_LABEL(byte[] _buffer) { buffer = _buffer; }

    /** TpmMarshaller method */
    @Override
    public void toTpm(TpmBuffer buf) { buf.writeSizedByteBuf(buffer); }

    /** TpmMarshaller method */
    @Override
    public void initFromTpm(TpmBuffer buf) { buffer = buf.readSizedByteBuf(); }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPM2B_LABEL fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(TPM2B_LABEL.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPM2B_LABEL fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPM2B_LABEL fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(TPM2B_LABEL.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("TPM2B_LABEL");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }

    @Override
    public void toStringInternal(TpmStructurePrinter _p, int d)
    {
        _p.add(d, "byte[]", "buffer", buffer);
    }
}

//<<<
