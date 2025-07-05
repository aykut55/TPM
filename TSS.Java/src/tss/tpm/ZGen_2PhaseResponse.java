package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** This command supports two-phase key exchange protocols. The command is used in
 *  combination with TPM2_EC_Ephemeral(). TPM2_EC_Ephemeral() generates an ephemeral key
 *  and returns the public point of that ephemeral key along with a numeric value that
 *  allows the TPM to regenerate the associated private key.
 */
public class ZGen_2PhaseResponse extends RespStructure
{
    /** X and Y coordinates of the computed value (scheme dependent) */
    public TPMS_ECC_POINT outZ1;

    /** X and Y coordinates of the second computed value (scheme dependent) */
    public TPMS_ECC_POINT outZ2;

    public ZGen_2PhaseResponse() {}

    /** TpmMarshaller method */
    @Override
    public void toTpm(TpmBuffer buf)
    {
        buf.writeSizedObj(outZ1);
        buf.writeSizedObj(outZ2);
    }

    /** TpmMarshaller method */
    @Override
    public void initFromTpm(TpmBuffer buf)
    {
        outZ1 = buf.createSizedObj(TPMS_ECC_POINT.class);
        outZ2 = buf.createSizedObj(TPMS_ECC_POINT.class);
    }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static ZGen_2PhaseResponse fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(ZGen_2PhaseResponse.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static ZGen_2PhaseResponse fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static ZGen_2PhaseResponse fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(ZGen_2PhaseResponse.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("ZGen_2PhaseResponse");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }

    @Override
    public void toStringInternal(TpmStructurePrinter _p, int d)
    {
        _p.add(d, "TPMS_ECC_POINT", "outZ1", outZ1);
        _p.add(d, "TPMS_ECC_POINT", "outZ2", outZ2);
    }

    @Override
    public SessEncInfo sessEncInfo() { return new SessEncInfo(2, 1); }
}

//<<<
