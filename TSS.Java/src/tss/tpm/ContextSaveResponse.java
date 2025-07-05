package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** This command saves a session context, object context, or sequence object context
 *  outside the TPM.
 */
public class ContextSaveResponse extends RespStructure
{
    public TPMS_CONTEXT context;

    public ContextSaveResponse() {}

    /** TpmMarshaller method */
    @Override
    public void toTpm(TpmBuffer buf) { context.toTpm(buf); }

    /** TpmMarshaller method */
    @Override
    public void initFromTpm(TpmBuffer buf) { context = TPMS_CONTEXT.fromTpm(buf); }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static ContextSaveResponse fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(ContextSaveResponse.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static ContextSaveResponse fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static ContextSaveResponse fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(ContextSaveResponse.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("ContextSaveResponse");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }

    @Override
    public void toStringInternal(TpmStructurePrinter _p, int d)
    {
        _p.add(d, "TPMS_CONTEXT", "context", context);
    }
}

//<<<
