package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** This command returns the values of all PCR specified in pcrSelectionIn. */
public class TPM2_PCR_Read_REQUEST extends ReqStructure
{
    /** The selection of PCR to read */
    public TPMS_PCR_SELECTION[] pcrSelectionIn;

    public TPM2_PCR_Read_REQUEST() {}

    /** @param _pcrSelectionIn The selection of PCR to read */
    public TPM2_PCR_Read_REQUEST(TPMS_PCR_SELECTION[] _pcrSelectionIn) { pcrSelectionIn = _pcrSelectionIn; }

    /** TpmMarshaller method */
    @Override
    public void toTpm(TpmBuffer buf) { buf.writeObjArr(pcrSelectionIn); }

    /** TpmMarshaller method */
    @Override
    public void initFromTpm(TpmBuffer buf) { pcrSelectionIn = buf.readObjArr(TPMS_PCR_SELECTION.class); }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPM2_PCR_Read_REQUEST fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(TPM2_PCR_Read_REQUEST.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPM2_PCR_Read_REQUEST fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPM2_PCR_Read_REQUEST fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(TPM2_PCR_Read_REQUEST.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("TPM2_PCR_Read_REQUEST");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }

    @Override
    public void toStringInternal(TpmStructurePrinter _p, int d)
    {
        _p.add(d, "TPMS_PCR_SELECTION[]", "pcrSelectionIn", pcrSelectionIn);
    }

    @Override
    public SessEncInfo sessEncInfo() { return new SessEncInfo(4, 3); }
}

//<<<
