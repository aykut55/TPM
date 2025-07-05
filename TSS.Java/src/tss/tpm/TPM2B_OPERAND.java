package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** This type is a sized buffer that can hold an operand for a comparison with an NV Index
 *  location. The maximum size of the operand is implementation dependent but a TPM is
 *  required to support an operand size that is at least as big as the digest produced by
 *  any of the hash algorithms implemented on the TPM.
 */
public class TPM2B_OPERAND extends TPM2B_DIGEST
{
    public TPM2B_OPERAND() {}

    /** @param _buffer The buffer area that can be no larger than a digest */
    public TPM2B_OPERAND(byte[] _buffer) { super(_buffer); }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPM2B_OPERAND fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(TPM2B_OPERAND.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPM2B_OPERAND fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPM2B_OPERAND fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(TPM2B_OPERAND.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("TPM2B_OPERAND");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }
}

//<<<
