package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** This is the format used for each of the authorizations in the session area of a command. */
public class TPMS_AUTH_COMMAND extends TpmStructure
{
    /** The session handle */
    public TPM_HANDLE sessionHandle;

    /** The session nonce, may be the Empty Buffer */
    public byte[] nonce;

    /** The session attributes */
    public TPMA_SESSION sessionAttributes;

    /** Either an HMAC, a password, or an EmptyAuth */
    public byte[] hmac;

    public TPMS_AUTH_COMMAND() { sessionHandle = new TPM_HANDLE(); }

    /** @param _sessionHandle The session handle
     *  @param _nonce The session nonce, may be the Empty Buffer
     *  @param _sessionAttributes The session attributes
     *  @param _hmac Either an HMAC, a password, or an EmptyAuth
     */
    public TPMS_AUTH_COMMAND(TPM_HANDLE _sessionHandle, byte[] _nonce, TPMA_SESSION _sessionAttributes, byte[] _hmac)
    {
        sessionHandle = _sessionHandle;
        nonce = _nonce;
        sessionAttributes = _sessionAttributes;
        hmac = _hmac;
    }

    /** TpmMarshaller method */
    @Override
    public void toTpm(TpmBuffer buf)
    {
        sessionHandle.toTpm(buf);
        buf.writeSizedByteBuf(nonce);
        sessionAttributes.toTpm(buf);
        buf.writeSizedByteBuf(hmac);
    }

    /** TpmMarshaller method */
    @Override
    public void initFromTpm(TpmBuffer buf)
    {
        sessionHandle = TPM_HANDLE.fromTpm(buf);
        nonce = buf.readSizedByteBuf();
        sessionAttributes = TPMA_SESSION.fromTpm(buf);
        hmac = buf.readSizedByteBuf();
    }

    /** @deprecated Use {@link #toBytes()} instead
     *  @return Wire (marshaled) representation of this object
     */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMS_AUTH_COMMAND fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(TPMS_AUTH_COMMAND.class);
    }

    /** @deprecated Use {@link #fromBytes(byte[])} instead
     *  @param byteBuf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMS_AUTH_COMMAND fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper
     *  @param buf Wire representation of the object
     *  @return New object constructed from its wire representation
     */
    public static TPMS_AUTH_COMMAND fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(TPMS_AUTH_COMMAND.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("TPMS_AUTH_COMMAND");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }

    @Override
    public void toStringInternal(TpmStructurePrinter _p, int d)
    {
        _p.add(d, "TPM_HANDLE", "sessionHandle", sessionHandle);
        _p.add(d, "byte[]", "nonce", nonce);
        _p.add(d, "TPMA_SESSION", "sessionAttributes", sessionAttributes);
        _p.add(d, "byte[]", "hmac", hmac);
    }
}

//<<<
