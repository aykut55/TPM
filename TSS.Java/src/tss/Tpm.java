package tss;

import tss.tpm.*;


// -----------This is an auto-generated file: do not edit

//>>>
/** The Tpm class provides Java functions to program a TPM.
 *  <P>
 *  The TPM spec defines TPM command with names like TPM2_PCR_Read().
 *  The Java rendering of the spec drops the 'TPM2_' prefix: e.g. PCR_Read().
 *  The Tpm and TpmBase classes also provide a few helper-functions: for example,
 *  the command _allowErrors() tells to not throw an exception if the next
 *  TPM command returns an error. Such helpers have names beginning with underscore '_'.
 *  <P>
 *  Tpm objects must be "connected" to a physical TPM or TPM simulator using the _setDevice()
 *  method.  Some devices (like the TPM simulator) need to be configured before they can
 *  be used.
 *  See the sample code that is part of the TSS.Java distribution for more information.
 */
public class Tpm extends TpmBase
{
    /** TPM2_Startup() is always preceded by _TPM_Init, which is the physical indication that
     *  TPM initialization is necessary because of a system-wide reset. TPM2_Startup() is only
     *  valid after _TPM_Init. Additional TPM2_Startup() commands are not allowed after it has
     *  completed successfully. If a TPM requires TPM2_Startup() and another command is
     *  received, or if the TPM receives TPM2_Startup() when it is not required, the TPM shall
     *  return TPM_RC_INITIALIZE.

     *  @param startupType TPM_SU_CLEAR or TPM_SU_STATE
     */
    public void Startup(TPM_SU startupType)
    {
        TPM2_Startup_REQUEST req = new TPM2_Startup_REQUEST(startupType);
        DispatchCommand(TPM_CC.Startup, req, null);
        return;
    }

    /** This command is used to prepare the TPM for a power cycle. The shutdownType parameter
     *  indicates how the subsequent TPM2_Startup() will be processed.

     *  @param shutdownType TPM_SU_CLEAR or TPM_SU_STATE
     */
    public void Shutdown(TPM_SU shutdownType)
    {
        TPM2_Shutdown_REQUEST req = new TPM2_Shutdown_REQUEST(shutdownType);
        DispatchCommand(TPM_CC.Shutdown, req, null);
        return;
    }

    /** This command causes the TPM to perform a test of its capabilities. If the fullTest is
     *  YES, the TPM will test all functions. If fullTest = NO, the TPM will only test those
     *  functions that have not previously been tested.

     *  @param fullTest YES if full test to be performed
     *         NO if only test of untested functions required
     */
    public void SelfTest(byte fullTest)
    {
        TPM2_SelfTest_REQUEST req = new TPM2_SelfTest_REQUEST(fullTest);
        DispatchCommand(TPM_CC.SelfTest, req, null);
        return;
    }

    /** This command causes the TPM to perform a test of the selected algorithms.

     *  @param toTest List of algorithms that should be tested
     *  @return toDoList - List of algorithms that need testing
     */
    public TPM_ALG_ID[] IncrementalSelfTest(TPM_ALG_ID[] toTest)
    {
        TPM2_IncrementalSelfTest_REQUEST req = new TPM2_IncrementalSelfTest_REQUEST(toTest);
        IncrementalSelfTestResponse resp = new IncrementalSelfTestResponse();
        DispatchCommand(TPM_CC.IncrementalSelfTest, req, resp);
        return resp.toDoList;
    }

    /** This command returns manufacturer-specific information regarding the results of a
     *  self-test and an indication of the test status.

     *  @return outData - Test result data
     *                    contains manufacturer-specific information<br>
     *          testResult - TBD
     */
    public GetTestResultResponse GetTestResult()
    {
        TPM2_GetTestResult_REQUEST req = new TPM2_GetTestResult_REQUEST();
        GetTestResultResponse resp = new GetTestResultResponse();
        DispatchCommand(TPM_CC.GetTestResult, req, resp);
        return resp;
    }

    /** This command is used to start an authorization session using alternative methods of
     *  establishing the session key (sessionKey). The session key is then used to derive
     *  values used for authorization and for encrypting parameters.

     *  @param tpmKey Handle of a loaded decrypt key used to encrypt salt
     *         may be TPM_RH_NULL
     *         Auth Index: None
     *  @param bind Entity providing the authValue
     *         may be TPM_RH_NULL
     *         Auth Index: None
     *  @param nonceCaller Initial nonceCaller, sets nonceTPM size for the session
     *         shall be at least 16 octets
     *  @param encryptedSalt Value encrypted according to the type of tpmKey
     *         If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer.
     *  @param sessionType Indicates the type of the session; simple HMAC or policy (including
     *  a
     *         trial policy)
     *  @param symmetric The algorithm and key size for parameter encryption
     *         may select TPM_ALG_NULL
     *  @param authHash Hash algorithm to use for the session
     *         Shall be a hash algorithm supported by the TPM and not TPM_ALG_NULL
     *  @return handle - Handle for the newly created session<br>
     *          nonceTPM - The initial nonce from the TPM, used in the computation of the sessionKey
     */
    public StartAuthSessionResponse StartAuthSession(TPM_HANDLE tpmKey, TPM_HANDLE bind, byte[] nonceCaller, byte[] encryptedSalt, TPM_SE sessionType, TPMT_SYM_DEF symmetric, TPM_ALG_ID authHash)
    {
        TPM2_StartAuthSession_REQUEST req = new TPM2_StartAuthSession_REQUEST(tpmKey, bind, nonceCaller, encryptedSalt, sessionType, symmetric, authHash);
        StartAuthSessionResponse resp = new StartAuthSessionResponse();
        DispatchCommand(TPM_CC.StartAuthSession, req, resp);
        return resp;
    }

    /** This command allows a policy authorization session to be returned to its initial
     *  state. This command is used after the TPM returns TPM_RC_PCR_CHANGED. That response
     *  code indicates that a policy will fail because the PCR have changed after
     *  TPM2_PolicyPCR() was executed. Restarting the session allows the authorizations to be
     *  replayed because the session restarts with the same nonceTPM. If the PCR are valid for
     *  the policy, the policy may then succeed.

     *  @param sessionHandle The handle for the policy session
     */
    public void PolicyRestart(TPM_HANDLE sessionHandle)
    {
        TPM2_PolicyRestart_REQUEST req = new TPM2_PolicyRestart_REQUEST(sessionHandle);
        DispatchCommand(TPM_CC.PolicyRestart, req, null);
        return;
    }

    /** This command is used to create an object that can be loaded into a TPM using
     *  TPM2_Load(). If the command completes successfully, the TPM will create the new object
     *  and return the objects creation data (creationData), its public area (outPublic), and
     *  its encrypted sensitive area (outPrivate). Preservation of the returned data is the
     *  responsibility of the caller. The object will need to be loaded (TPM2_Load()) before
     *  it may be used. The only difference between the inPublic TPMT_PUBLIC template and the
     *  outPublic TPMT_PUBLIC object is in the unique field.

     *  @param parentHandle Handle of parent for new object
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param inSensitive The sensitive data
     *  @param inPublic The public template
     *  @param outsideInfo Data that will be included in the creation data for this object to
     *         provide permanent, verifiable linkage between this object and some object owner
     *  data
     *  @param creationPCR PCR that will be used in creation data
     *  @return outPrivate - The private portion of the object<br>
     *          outPublic - The public portion of the created object<br>
     *          creationData - Contains a TPMS_CREATION_DATA<br>
     *          creationHash - Digest of creationData using nameAlg of outPublic<br>
     *          creationTicket - Ticket used by TPM2_CertifyCreation() to validate that the
     *                           creation data was produced by the TPM
     */
    public CreateResponse Create(TPM_HANDLE parentHandle, TPMS_SENSITIVE_CREATE inSensitive, TPMT_PUBLIC inPublic, byte[] outsideInfo, TPMS_PCR_SELECTION[] creationPCR)
    {
        TPM2_Create_REQUEST req = new TPM2_Create_REQUEST(parentHandle, inSensitive, inPublic, outsideInfo, creationPCR);
        CreateResponse resp = new CreateResponse();
        DispatchCommand(TPM_CC.Create, req, resp);
        return resp;
    }

    /** This command is used to load objects into the TPM. This command is used when both a
     *  TPM2B_PUBLIC and TPM2B_PRIVATE are to be loaded. If only a TPM2B_PUBLIC is to be
     *  loaded, the TPM2_LoadExternal command is used.

     *  @param parentHandle TPM handle of parent key; shall not be a reserved handle
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param inPrivate The private portion of the object
     *  @param inPublic The public portion of the object
     *  @return handle - Handle of type TPM_HT_TRANSIENT for the loaded object
     */
    public TPM_HANDLE Load(TPM_HANDLE parentHandle, TPM2B_PRIVATE inPrivate, TPMT_PUBLIC inPublic)
    {
        TPM2_Load_REQUEST req = new TPM2_Load_REQUEST(parentHandle, inPrivate, inPublic);
        LoadResponse resp = new LoadResponse();
        DispatchCommand(TPM_CC.Load, req, resp);
        return resp.handle;
    }

    /** This command is used to load an object that is not a Protected Object into the TPM.
     *  The command allows loading of a public area or both a public and sensitive area.

     *  @param inPrivate The sensitive portion of the object (optional)
     *  @param inPublic The public portion of the object
     *  @param hierarchy Hierarchy with which the object area is associated
     *  @return handle - Handle of type TPM_HT_TRANSIENT for the loaded object
     */
    public TPM_HANDLE LoadExternal(TPMT_SENSITIVE inPrivate, TPMT_PUBLIC inPublic, TPM_HANDLE hierarchy)
    {
        TPM2_LoadExternal_REQUEST req = new TPM2_LoadExternal_REQUEST(inPrivate, inPublic, hierarchy);
        LoadExternalResponse resp = new LoadExternalResponse();
        DispatchCommand(TPM_CC.LoadExternal, req, resp);
        return resp.handle;
    }

    /** This command allows access to the public area of a loaded object.

     *  @param objectHandle TPM handle of an object
     *         Auth Index: None
     *  @return outPublic - Structure containing the public area of an object<br>
     *          name - Name of the object<br>
     *          qualifiedName - The Qualified Name of the object
     */
    public ReadPublicResponse ReadPublic(TPM_HANDLE objectHandle)
    {
        TPM2_ReadPublic_REQUEST req = new TPM2_ReadPublic_REQUEST(objectHandle);
        ReadPublicResponse resp = new ReadPublicResponse();
        DispatchCommand(TPM_CC.ReadPublic, req, resp);
        return resp;
    }

    /** This command enables the association of a credential with an object in a way that
     *  ensures that the TPM has validated the parameters of the credentialed object.

     *  @param activateHandle Handle of the object associated with certificate in credentialBlob
     *         Auth Index: 1
     *         Auth Role: ADMIN
     *  @param keyHandle Loaded key used to decrypt the TPMS_SENSITIVE in credentialBlob
     *         Auth Index: 2
     *         Auth Role: USER
     *  @param credentialBlob The credential
     *  @param secret KeyHandle algorithm-dependent encrypted seed that protects credentialBlob
     *  @return certInfo - The decrypted certificate information
     *                     the data should be no larger than the size of the digest of the nameAlg
     *                     associated with keyHandle
     */
    public byte[] ActivateCredential(TPM_HANDLE activateHandle, TPM_HANDLE keyHandle, TPMS_ID_OBJECT credentialBlob, byte[] secret)
    {
        TPM2_ActivateCredential_REQUEST req = new TPM2_ActivateCredential_REQUEST(activateHandle, keyHandle, credentialBlob, secret);
        ActivateCredentialResponse resp = new ActivateCredentialResponse();
        DispatchCommand(TPM_CC.ActivateCredential, req, resp);
        return resp.certInfo;
    }

    /** This command allows the TPM to perform the actions required of a Certificate Authority
     *  (CA) in creating a TPM2B_ID_OBJECT containing an activation credential.

     *  @param handle Loaded public area, used to encrypt the sensitive area containing the
     *         credential key
     *         Auth Index: None
     *  @param credential The credential information
     *  @param objectName Name of the object to which the credential applies
     *  @return credentialBlob - The credential<br>
     *          secret - Handle algorithm-dependent data that wraps the key that encrypts credentialBlob
     */
    public MakeCredentialResponse MakeCredential(TPM_HANDLE handle, byte[] credential, byte[] objectName)
    {
        TPM2_MakeCredential_REQUEST req = new TPM2_MakeCredential_REQUEST(handle, credential, objectName);
        MakeCredentialResponse resp = new MakeCredentialResponse();
        DispatchCommand(TPM_CC.MakeCredential, req, resp);
        return resp;
    }

    /** This command returns the data in a loaded Sealed Data Object.

     *  @param itemHandle Handle of a loaded data object
     *         Auth Index: 1
     *         Auth Role: USER
     *  @return outData - Unsealed data
     *                    Size of outData is limited to be no more than 128 octets.
     */
    public byte[] Unseal(TPM_HANDLE itemHandle)
    {
        TPM2_Unseal_REQUEST req = new TPM2_Unseal_REQUEST(itemHandle);
        UnsealResponse resp = new UnsealResponse();
        DispatchCommand(TPM_CC.Unseal, req, resp);
        return resp.outData;
    }

    /** This command is used to change the authorization secret for a TPM-resident object.

     *  @param objectHandle Handle of the object
     *         Auth Index: 1
     *         Auth Role: ADMIN
     *  @param parentHandle Handle of the parent
     *         Auth Index: None
     *  @param newAuth New authorization value
     *  @return outPrivate - Private area containing the new authorization value
     */
    public TPM2B_PRIVATE ObjectChangeAuth(TPM_HANDLE objectHandle, TPM_HANDLE parentHandle, byte[] newAuth)
    {
        TPM2_ObjectChangeAuth_REQUEST req = new TPM2_ObjectChangeAuth_REQUEST(objectHandle, parentHandle, newAuth);
        ObjectChangeAuthResponse resp = new ObjectChangeAuthResponse();
        DispatchCommand(TPM_CC.ObjectChangeAuth, req, resp);
        return resp.outPrivate;
    }

    /** This command creates an object and loads it in the TPM. This command allows creation
     *  of any type of object (Primary, Ordinary, or Derived) depending on the type of
     *  parentHandle. If parentHandle references a Primary Seed, then a Primary Object is
     *  created; if parentHandle references a Storage Parent, then an Ordinary Object is
     *  created; and if parentHandle references a Derivation Parent, then a Derived Object is generated.

     *  @param parentHandle Handle of a transient storage key, a persistent storage key,
     *         TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param inSensitive The sensitive data, see TPM 2.0 Part 1 Sensitive Values
     *  @param inPublic The public template
     *  @return handle - Handle of type TPM_HT_TRANSIENT for created object<br>
     *          outPrivate - The sensitive area of the object (optional)<br>
     *          outPublic - The public portion of the created object<br>
     *          name - The name of the created object
     */
    public CreateLoadedResponse CreateLoaded(TPM_HANDLE parentHandle, TPMS_SENSITIVE_CREATE inSensitive, byte[] inPublic)
    {
        TPM2_CreateLoaded_REQUEST req = new TPM2_CreateLoaded_REQUEST(parentHandle, inSensitive, inPublic);
        CreateLoadedResponse resp = new CreateLoadedResponse();
        DispatchCommand(TPM_CC.CreateLoaded, req, resp);
        return resp;
    }

    /** This command duplicates a loaded object so that it may be used in a different
     *  hierarchy. The new parent key for the duplicate may be on the same or different TPM or
     *  TPM_RH_NULL. Only the public area of newParentHandle is required to be loaded.

     *  @param objectHandle Loaded object to duplicate
     *         Auth Index: 1
     *         Auth Role: DUP
     *  @param newParentHandle Shall reference the public area of an asymmetric key
     *         Auth Index: None
     *  @param encryptionKeyIn Optional symmetric encryption key
     *         The size for this key is set to zero when the TPM is to generate the key. This
     *         parameter may be encrypted.
     *  @param symmetricAlg Definition for the symmetric algorithm to be used for the inner wrapper
     *         may be TPM_ALG_NULL if no inner wrapper is applied
     *  @return encryptionKeyOut - If the caller provided an encryption key or if symmetricAlg
     *  was
     *                             TPM_ALG_NULL, then this will be the Empty Buffer;
     *  otherwise, it
     *                             shall contain the TPM-generated, symmetric encryption key for
     *                             the inner wrapper.<br>
     *          duplicate - Private area that may be encrypted by encryptionKeyIn; and may be
     *                      doubly encrypted<br>
     *          outSymSeed - Seed protected by the asymmetric algorithms of new parent (NP)
     */
    public DuplicateResponse Duplicate(TPM_HANDLE objectHandle, TPM_HANDLE newParentHandle, byte[] encryptionKeyIn, TPMT_SYM_DEF_OBJECT symmetricAlg)
    {
        TPM2_Duplicate_REQUEST req = new TPM2_Duplicate_REQUEST(objectHandle, newParentHandle, encryptionKeyIn, symmetricAlg);
        DuplicateResponse resp = new DuplicateResponse();
        DispatchCommand(TPM_CC.Duplicate, req, resp);
        return resp;
    }

    /** This command allows the TPM to serve in the role as a Duplication Authority. If proper
     *  authorization for use of the oldParent is provided, then an HMAC key and a symmetric
     *  key are recovered from inSymSeed and used to integrity check and decrypt inDuplicate.
     *  A new protection seed value is generated according to the methods appropriate for
     *  newParent and the blob is re-encrypted and a new integrity value is computed. The
     *  re-encrypted blob is returned in outDuplicate and the symmetric key returned in outSymKey.

     *  @param oldParent Parent of object
     *         Auth Index: 1
     *         Auth Role: User
     *  @param newParent New parent of the object
     *         Auth Index: None
     *  @param inDuplicate An object encrypted using symmetric key derived from inSymSeed
     *  @param name The Name of the object being rewrapped
     *  @param inSymSeed The seed for the symmetric key and HMAC key
     *         needs oldParent private key to recover the seed and generate the symmetric key
     *  @return outDuplicate - An object encrypted using symmetric key derived from outSymSeed<br>
     *          outSymSeed - Seed for a symmetric key protected by newParent asymmetric key
     */
    public RewrapResponse Rewrap(TPM_HANDLE oldParent, TPM_HANDLE newParent, TPM2B_PRIVATE inDuplicate, byte[] name, byte[] inSymSeed)
    {
        TPM2_Rewrap_REQUEST req = new TPM2_Rewrap_REQUEST(oldParent, newParent, inDuplicate, name, inSymSeed);
        RewrapResponse resp = new RewrapResponse();
        DispatchCommand(TPM_CC.Rewrap, req, resp);
        return resp;
    }

    /** This command allows an object to be encrypted using the symmetric encryption values of
     *  a Storage Key. After encryption, the object may be loaded and used in the new
     *  hierarchy. The imported object (duplicate) may be singly encrypted, multiply
     *  encrypted, or unencrypted.

     *  @param parentHandle The handle of the new parent for the object
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param encryptionKey The optional symmetric encryption key used as the inner wrapper
     *  for duplicate
     *         If symmetricAlg is TPM_ALG_NULL, then this parameter shall be the Empty Buffer.
     *  @param objectPublic The public area of the object to be imported
     *         This is provided so that the integrity value for duplicate and the object
     *         attributes can be checked.
     *         NOTE Even if the integrity value of the object is not checked on input, the object
     *         Name is required to create the integrity value for the imported object.
     *  @param duplicate The symmetrically encrypted duplicate object that may contain an inner
     *         symmetric wrapper
     *  @param inSymSeed The seed for the symmetric key and HMAC key
     *         inSymSeed is encrypted/encoded using the algorithms of newParent.
     *  @param symmetricAlg Definition for the symmetric algorithm to use for the inner wrapper
     *         If this algorithm is TPM_ALG_NULL, no inner wrapper is present and encryptionKey
     *         shall be the Empty Buffer.
     *  @return outPrivate - The sensitive area encrypted with the symmetric key of parentHandle
     */
    public TPM2B_PRIVATE Import(TPM_HANDLE parentHandle, byte[] encryptionKey, TPMT_PUBLIC objectPublic, TPM2B_PRIVATE duplicate, byte[] inSymSeed, TPMT_SYM_DEF_OBJECT symmetricAlg)
    {
        TPM2_Import_REQUEST req = new TPM2_Import_REQUEST(parentHandle, encryptionKey, objectPublic, duplicate, inSymSeed, symmetricAlg);
        ImportResponse resp = new ImportResponse();
        DispatchCommand(TPM_CC.Import, req, resp);
        return resp.outPrivate;
    }

    /** This command performs RSA encryption using the indicated padding scheme according to
     *  IETF RFC 8017. If the scheme of keyHandle is TPM_ALG_NULL, then the caller may use
     *  inScheme to specify the padding scheme. If scheme of keyHandle is not TPM_ALG_NULL,
     *  then inScheme shall either be TPM_ALG_NULL or be the same as scheme (TPM_RC_SCHEME).

     *  @param keyHandle Reference to public portion of RSA key to use for encryption
     *         Auth Index: None
     *  @param message Message to be encrypted
     *         NOTE 1 The data type was chosen because it limits the overall size of the input
     *  to
     *         no greater than the size of the largest RSA public key. This may be larger than
     *         allowed for keyHandle.
     *  @param inScheme The padding scheme to use if scheme associated with keyHandle is TPM_ALG_NULL
     *         One of: TPMS_KEY_SCHEME_ECDH, TPMS_KEY_SCHEME_ECMQV, TPMS_SIG_SCHEME_RSASSA,
     *         TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA, TPMS_SIG_SCHEME_ECDAA,
     *         TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR, TPMS_ENC_SCHEME_RSAES,
     *         TPMS_ENC_SCHEME_OAEP, TPMS_SCHEME_HASH, TPMS_NULL_ASYM_SCHEME.
     *  @param label Optional label L to be associated with the message
     *         Size of the buffer is zero if no label is present
     *         NOTE 2 See description of label above.
     *  @return outData - Encrypted output
     */
    public byte[] RSA_Encrypt(TPM_HANDLE keyHandle, byte[] message, TPMU_ASYM_SCHEME inScheme, byte[] label)
    {
        TPM2_RSA_Encrypt_REQUEST req = new TPM2_RSA_Encrypt_REQUEST(keyHandle, message, inScheme, label);
        RSA_EncryptResponse resp = new RSA_EncryptResponse();
        DispatchCommand(TPM_CC.RSA_Encrypt, req, resp);
        return resp.outData;
    }

    /** This command performs RSA decryption using the indicated padding scheme according to
     *  IETF RFC 8017 ((PKCS#1).

     *  @param keyHandle RSA key to use for decryption
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param cipherText Cipher text to be decrypted
     *         NOTE An encrypted RSA data block is the size of the public modulus.
     *  @param inScheme The padding scheme to use if scheme associated with keyHandle is TPM_ALG_NULL
     *         One of: TPMS_KEY_SCHEME_ECDH, TPMS_KEY_SCHEME_ECMQV, TPMS_SIG_SCHEME_RSASSA,
     *         TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA, TPMS_SIG_SCHEME_ECDAA,
     *         TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR, TPMS_ENC_SCHEME_RSAES,
     *         TPMS_ENC_SCHEME_OAEP, TPMS_SCHEME_HASH, TPMS_NULL_ASYM_SCHEME.
     *  @param label Label whose association with the message is to be verified
     *  @return message - Decrypted output
     */
    public byte[] RSA_Decrypt(TPM_HANDLE keyHandle, byte[] cipherText, TPMU_ASYM_SCHEME inScheme, byte[] label)
    {
        TPM2_RSA_Decrypt_REQUEST req = new TPM2_RSA_Decrypt_REQUEST(keyHandle, cipherText, inScheme, label);
        RSA_DecryptResponse resp = new RSA_DecryptResponse();
        DispatchCommand(TPM_CC.RSA_Decrypt, req, resp);
        return resp.message;
    }

    /** This command uses the TPM to generate an ephemeral key pair (de, Qe where Qe [de]G).
     *  It uses the private ephemeral key and a loaded public key (QS) to compute the shared
     *  secret value (P [hde]QS).

     *  @param keyHandle Handle of a loaded ECC key public area.
     *         Auth Index: None
     *  @return zPoint - Results of P h[de]Qs<br>
     *          pubPoint - Generated ephemeral public point (Qe)
     */
    public ECDH_KeyGenResponse ECDH_KeyGen(TPM_HANDLE keyHandle)
    {
        TPM2_ECDH_KeyGen_REQUEST req = new TPM2_ECDH_KeyGen_REQUEST(keyHandle);
        ECDH_KeyGenResponse resp = new ECDH_KeyGenResponse();
        DispatchCommand(TPM_CC.ECDH_KeyGen, req, resp);
        return resp;
    }

    /** This command uses the TPM to recover the Z value from a public point (QB) and a
     *  private key (ds). It will perform the multiplication of the provided inPoint (QB) with
     *  the private key (ds) and return the coordinates of the resultant point (Z = (xZ , yZ)
     *  [hds]QB; where h is the cofactor of the curve).

     *  @param keyHandle Handle of a loaded ECC key
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param inPoint A public key
     *  @return outPoint - X and Y coordinates of the product of the multiplication Z = (xZ ,
     *  yZ) [hdS]QB
     */
    public TPMS_ECC_POINT ECDH_ZGen(TPM_HANDLE keyHandle, TPMS_ECC_POINT inPoint)
    {
        TPM2_ECDH_ZGen_REQUEST req = new TPM2_ECDH_ZGen_REQUEST(keyHandle, inPoint);
        ECDH_ZGenResponse resp = new ECDH_ZGenResponse();
        DispatchCommand(TPM_CC.ECDH_ZGen, req, resp);
        return resp.outPoint;
    }

    /** This command returns the parameters of an ECC curve identified by its TCG-assigned curveID.

     *  @param curveID Parameter set selector
     *  @return parameters - ECC parameters for the selected curve
     */
    public TPMS_ALGORITHM_DETAIL_ECC ECC_Parameters(TPM_ECC_CURVE curveID)
    {
        TPM2_ECC_Parameters_REQUEST req = new TPM2_ECC_Parameters_REQUEST(curveID);
        ECC_ParametersResponse resp = new ECC_ParametersResponse();
        DispatchCommand(TPM_CC.ECC_Parameters, req, resp);
        return resp.parameters;
    }

    /** This command supports two-phase key exchange protocols. The command is used in
     *  combination with TPM2_EC_Ephemeral(). TPM2_EC_Ephemeral() generates an ephemeral key
     *  and returns the public point of that ephemeral key along with a numeric value that
     *  allows the TPM to regenerate the associated private key.

     *  @param keyA Handle of an unrestricted decryption key ECC
     *         The private key referenced by this handle is used as dS,A
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param inQsB Other partys static public key (Qs,B = (Xs,B, Ys,B))
     *  @param inQeB Other party's ephemeral public key (Qe,B = (Xe,B, Ye,B))
     *  @param inScheme The key exchange scheme
     *  @param counter Value returned by TPM2_EC_Ephemeral()
     *  @return outZ1 - X and Y coordinates of the computed value (scheme dependent)<br>
     *          outZ2 - X and Y coordinates of the second computed value (scheme dependent)
     */
    public ZGen_2PhaseResponse ZGen_2Phase(TPM_HANDLE keyA, TPMS_ECC_POINT inQsB, TPMS_ECC_POINT inQeB, TPM_ALG_ID inScheme, int counter)
    {
        TPM2_ZGen_2Phase_REQUEST req = new TPM2_ZGen_2Phase_REQUEST(keyA, inQsB, inQeB, inScheme, counter);
        ZGen_2PhaseResponse resp = new ZGen_2PhaseResponse();
        DispatchCommand(TPM_CC.ZGen_2Phase, req, resp);
        return resp;
    }

    /** This command performs ECC encryption as described in Part 1, Annex D.

     *  @param keyHandle Reference to public portion of ECC key to use for encryption
     *         Auth Index: None
     *  @param plainText Plaintext to be encrypted
     *  @param inScheme The KDF to use if scheme associated with keyHandle is TPM_ALG_NULL
     *         One of: TPMS_KDF_SCHEME_MGF1, TPMS_KDF_SCHEME_KDF1_SP800_56A, TPMS_KDF_SCHEME_KDF2,
     *         TPMS_KDF_SCHEME_KDF1_SP800_108, TPMS_SCHEME_HASH, TPMS_NULL_KDF_SCHEME.
     *  @return C1 - The public ephemeral key used for ECDH<br>
     *          C2 - The data block produced by the XOR process<br>
     *          C3 - The integrity value
     */
    public ECC_EncryptResponse ECC_Encrypt(TPM_HANDLE keyHandle, byte[] plainText, TPMU_KDF_SCHEME inScheme)
    {
        TPM2_ECC_Encrypt_REQUEST req = new TPM2_ECC_Encrypt_REQUEST(keyHandle, plainText, inScheme);
        ECC_EncryptResponse resp = new ECC_EncryptResponse();
        DispatchCommand(TPM_CC.ECC_Encrypt, req, resp);
        return resp;
    }

    /** This command performs ECC decryption.

     *  @param keyHandle ECC key to use for decryption
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param C1 The public ephemeral key used for ECDH
     *  @param C2 The data block produced by the XOR process
     *  @param C3 The integrity value
     *  @param inScheme The KDF to use if scheme associated with keyHandle is TPM_ALG_NULL
     *         One of: TPMS_KDF_SCHEME_MGF1, TPMS_KDF_SCHEME_KDF1_SP800_56A, TPMS_KDF_SCHEME_KDF2,
     *         TPMS_KDF_SCHEME_KDF1_SP800_108, TPMS_SCHEME_HASH, TPMS_NULL_KDF_SCHEME.
     *  @return plainText - Decrypted output
     */
    public byte[] ECC_Decrypt(TPM_HANDLE keyHandle, TPMS_ECC_POINT C1, byte[] C2, byte[] C3, TPMU_KDF_SCHEME inScheme)
    {
        TPM2_ECC_Decrypt_REQUEST req = new TPM2_ECC_Decrypt_REQUEST(keyHandle, C1, C2, C3, inScheme);
        ECC_DecryptResponse resp = new ECC_DecryptResponse();
        DispatchCommand(TPM_CC.ECC_Decrypt, req, resp);
        return resp.plainText;
    }

    /** NOTE 1 This command is deprecated, and TPM2_EncryptDecrypt2() is preferred. This
     *  should be reflected in platform-specific specifications.

     *  @param keyHandle The symmetric key used for the operation
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param decrypt If YES, then the operation is decryption; if NO, the operation is encryption
     *  @param mode Symmetric encryption/decryption mode
     *         this field shall match the default mode of the key or be TPM_ALG_NULL.
     *  @param ivIn An initial value as required by the algorithm
     *  @param inData The data to be encrypted/decrypted
     *  @return outData - Encrypted or decrypted output<br>
     *          ivOut - Chaining value to use for IV in next round
     */
    public EncryptDecryptResponse EncryptDecrypt(TPM_HANDLE keyHandle, byte decrypt, TPM_ALG_ID mode, byte[] ivIn, byte[] inData)
    {
        TPM2_EncryptDecrypt_REQUEST req = new TPM2_EncryptDecrypt_REQUEST(keyHandle, decrypt, mode, ivIn, inData);
        EncryptDecryptResponse resp = new EncryptDecryptResponse();
        DispatchCommand(TPM_CC.EncryptDecrypt, req, resp);
        return resp;
    }

    /** This command is identical to TPM2_EncryptDecrypt(), except that the inData parameter
     *  is the first parameter. This permits inData to be parameter encrypted.

     *  @param keyHandle The symmetric key used for the operation
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param inData The data to be encrypted/decrypted
     *  @param decrypt If YES, then the operation is decryption; if NO, the operation is encryption
     *  @param mode Symmetric mode
     *         this field shall match the default mode of the key or be TPM_ALG_NULL.
     *  @param ivIn An initial value as required by the algorithm
     *  @return outData - Encrypted or decrypted output<br>
     *          ivOut - Chaining value to use for IV in next round
     */
    public EncryptDecrypt2Response EncryptDecrypt2(TPM_HANDLE keyHandle, byte[] inData, byte decrypt, TPM_ALG_ID mode, byte[] ivIn)
    {
        TPM2_EncryptDecrypt2_REQUEST req = new TPM2_EncryptDecrypt2_REQUEST(keyHandle, inData, decrypt, mode, ivIn);
        EncryptDecrypt2Response resp = new EncryptDecrypt2Response();
        DispatchCommand(TPM_CC.EncryptDecrypt2, req, resp);
        return resp;
    }

    /** This command performs a hash operation on a data buffer and returns the results.

     *  @param data Data to be hashed
     *  @param hashAlg Algorithm for the hash being computed shall not be TPM_ALG_NULL
     *  @param hierarchy Hierarchy to use for the ticket (TPM_RH_NULL allowed)
     *  @return outHash - Results<br>
     *          validation - Ticket indicating that the sequence of octets used to compute
     *                       outDigest did not start with TPM_GENERATED_VALUE
     *                       will be a NULL ticket if the digest may not be signed with a
     *                       restricted key
     */
    public HashResponse Hash(byte[] data, TPM_ALG_ID hashAlg, TPM_HANDLE hierarchy)
    {
        TPM2_Hash_REQUEST req = new TPM2_Hash_REQUEST(data, hashAlg, hierarchy);
        HashResponse resp = new HashResponse();
        DispatchCommand(TPM_CC.Hash, req, resp);
        return resp;
    }

    /** This command performs an HMAC on the supplied data using the indicated hash algorithm.

     *  @param handle Handle for the symmetric signing key providing the HMAC key
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param buffer HMAC data
     *  @param hashAlg Algorithm to use for HMAC
     *  @return outHMAC - The returned HMAC in a sized buffer
     */
    public byte[] HMAC(TPM_HANDLE handle, byte[] buffer, TPM_ALG_ID hashAlg)
    {
        TPM2_HMAC_REQUEST req = new TPM2_HMAC_REQUEST(handle, buffer, hashAlg);
        HMACResponse resp = new HMACResponse();
        DispatchCommand(TPM_CC.HMAC, req, resp);
        return resp.outHMAC;
    }

    /** This command performs an HMAC or a block cipher MAC on the supplied data using the
     *  indicated algorithm.

     *  @param handle Handle for the symmetric signing key providing the MAC key
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param buffer MAC data
     *  @param inScheme Algorithm to use for MAC
     *  @return outMAC - The returned MAC in a sized buffer
     */
    public byte[] MAC(TPM_HANDLE handle, byte[] buffer, TPM_ALG_ID inScheme)
    {
        TPM2_MAC_REQUEST req = new TPM2_MAC_REQUEST(handle, buffer, inScheme);
        MACResponse resp = new MACResponse();
        DispatchCommand(TPM_CC.MAC, req, resp);
        return resp.outMAC;
    }

    /** This command returns the next bytesRequested octets from the random number generator (RNG).

     *  @param bytesRequested Number of octets to return
     *  @return randomBytes - The random octets
     */
    public byte[] GetRandom(int bytesRequested)
    {
        TPM2_GetRandom_REQUEST req = new TPM2_GetRandom_REQUEST(bytesRequested);
        GetRandomResponse resp = new GetRandomResponse();
        DispatchCommand(TPM_CC.GetRandom, req, resp);
        return resp.randomBytes;
    }

    /** This command is used to add "additional information" to the RNG state.

     *  @param inData Additional information
     */
    public void StirRandom(byte[] inData)
    {
        TPM2_StirRandom_REQUEST req = new TPM2_StirRandom_REQUEST(inData);
        DispatchCommand(TPM_CC.StirRandom, req, null);
        return;
    }

    /** This command starts an HMAC sequence. The TPM will create and initialize an HMAC
     *  sequence structure, assign a handle to the sequence, and set the authValue of the
     *  sequence object to the value in auth.

     *  @param handle Handle of an HMAC key
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param auth Authorization value for subsequent use of the sequence
     *  @param hashAlg The hash algorithm to use for the HMAC
     *  @return handle - A handle to reference the sequence
     */
    public TPM_HANDLE HMAC_Start(TPM_HANDLE handle, byte[] auth, TPM_ALG_ID hashAlg)
    {
        TPM2_HMAC_Start_REQUEST req = new TPM2_HMAC_Start_REQUEST(handle, auth, hashAlg);
        HMAC_StartResponse resp = new HMAC_StartResponse();
        DispatchCommand(TPM_CC.HMAC_Start, req, resp);
        return resp.handle;
    }

    /** This command starts a MAC sequence. The TPM will create and initialize a MAC sequence
     *  structure, assign a handle to the sequence, and set the authValue of the sequence
     *  object to the value in auth.

     *  @param handle Handle of a MAC key
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param auth Authorization value for subsequent use of the sequence
     *  @param inScheme The algorithm to use for the MAC
     *  @return handle - A handle to reference the sequence
     */
    public TPM_HANDLE MAC_Start(TPM_HANDLE handle, byte[] auth, TPM_ALG_ID inScheme)
    {
        TPM2_MAC_Start_REQUEST req = new TPM2_MAC_Start_REQUEST(handle, auth, inScheme);
        MAC_StartResponse resp = new MAC_StartResponse();
        DispatchCommand(TPM_CC.MAC_Start, req, resp);
        return resp.handle;
    }

    /** This command starts a hash or an Event Sequence. If hashAlg is an implemented hash,
     *  then a hash sequence is started. If hashAlg is TPM_ALG_NULL, then an Event Sequence is
     *  started. If hashAlg is neither an implemented algorithm nor TPM_ALG_NULL, then the TPM
     *  shall return TPM_RC_HASH.

     *  @param auth Authorization value for subsequent use of the sequence
     *  @param hashAlg The hash algorithm to use for the hash sequence
     *         An Event Sequence starts if this is TPM_ALG_NULL.
     *  @return handle - A handle to reference the sequence
     */
    public TPM_HANDLE HashSequenceStart(byte[] auth, TPM_ALG_ID hashAlg)
    {
        TPM2_HashSequenceStart_REQUEST req = new TPM2_HashSequenceStart_REQUEST(auth, hashAlg);
        HashSequenceStartResponse resp = new HashSequenceStartResponse();
        DispatchCommand(TPM_CC.HashSequenceStart, req, resp);
        return resp.handle;
    }

    /** This command is used to add data to a hash or HMAC sequence. The amount of data in
     *  buffer may be any size up to the limits of the TPM.

     *  @param sequenceHandle Handle for the sequence object
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param buffer Data to be added to hash
     */
    public void SequenceUpdate(TPM_HANDLE sequenceHandle, byte[] buffer)
    {
        TPM2_SequenceUpdate_REQUEST req = new TPM2_SequenceUpdate_REQUEST(sequenceHandle, buffer);
        DispatchCommand(TPM_CC.SequenceUpdate, req, null);
        return;
    }

    /** This command adds the last part of data, if any, to a hash/HMAC sequence and returns
     *  the result.

     *  @param sequenceHandle Authorization for the sequence
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param buffer Data to be added to the hash/HMAC
     *  @param hierarchy Hierarchy of the ticket for a hash
     *  @return result - The returned HMAC or digest in a sized buffer<br>
     *          validation - Ticket indicating that the sequence of octets used to compute
     *                       outDigest did not start with TPM_GENERATED_VALUE
     *                       This is a NULL Ticket when the sequence is HMAC.
     */
    public SequenceCompleteResponse SequenceComplete(TPM_HANDLE sequenceHandle, byte[] buffer, TPM_HANDLE hierarchy)
    {
        TPM2_SequenceComplete_REQUEST req = new TPM2_SequenceComplete_REQUEST(sequenceHandle, buffer, hierarchy);
        SequenceCompleteResponse resp = new SequenceCompleteResponse();
        DispatchCommand(TPM_CC.SequenceComplete, req, resp);
        return resp;
    }

    /** This command adds the last part of data, if any, to an Event Sequence and returns the
     *  result in a digest list. If pcrHandle references a PCR and not TPM_RH_NULL, then the
     *  returned digest list is processed in the same manner as the digest list input
     *  parameter to TPM2_PCR_Extend(). That is, if a bank contains a PCR associated with
     *  pcrHandle, it is extended with the associated digest value from the list.

     *  @param pcrHandle PCR to be extended with the Event data
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param sequenceHandle Authorization for the sequence
     *         Auth Index: 2
     *         Auth Role: USER
     *  @param buffer Data to be added to the Event
     *  @return results - List of digests computed for the PCR
     */
    public TPMT_HA[] EventSequenceComplete(TPM_HANDLE pcrHandle, TPM_HANDLE sequenceHandle, byte[] buffer)
    {
        TPM2_EventSequenceComplete_REQUEST req = new TPM2_EventSequenceComplete_REQUEST(pcrHandle, sequenceHandle, buffer);
        EventSequenceCompleteResponse resp = new EventSequenceCompleteResponse();
        DispatchCommand(TPM_CC.EventSequenceComplete, req, resp);
        return resp.results;
    }

    /** The purpose of this command is to prove that an object with a specific Name is loaded
     *  in the TPM. By certifying that the object is loaded, the TPM warrants that a public
     *  area with a given Name is self-consistent and associated with a valid sensitive area.
     *  If a relying party has a public area that has the same Name as a Name certified with
     *  this command, then the values in that public area are correct.

     *  @param objectHandle Handle of the object to be certified
     *         Auth Index: 1
     *         Auth Role: ADMIN
     *  @param signHandle Handle of the key used to sign the attestation structure
     *         Auth Index: 2
     *         Auth Role: USER
     *  @param qualifyingData User provided qualifying data
     *  @param inScheme Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
     *         One of: TPMS_SIG_SCHEME_RSASSA, TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA,
     *         TPMS_SIG_SCHEME_ECDAA, TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR,
     *         TPMS_SCHEME_HMAC, TPMS_SCHEME_HASH, TPMS_NULL_SIG_SCHEME.
     *  @return certifyInfo - The structure that was signed<br>
     *          signature - The asymmetric signature over certifyInfo using the key referenced
     *  by signHandle
     */
    public CertifyResponse Certify(TPM_HANDLE objectHandle, TPM_HANDLE signHandle, byte[] qualifyingData, TPMU_SIG_SCHEME inScheme)
    {
        TPM2_Certify_REQUEST req = new TPM2_Certify_REQUEST(objectHandle, signHandle, qualifyingData, inScheme);
        CertifyResponse resp = new CertifyResponse();
        DispatchCommand(TPM_CC.Certify, req, resp);
        return resp;
    }

    /** This command is used to prove the association between an object and its creation data.
     *  The TPM will validate that the ticket was produced by the TPM and that the ticket
     *  validates the association between a loaded public area and the provided hash of the
     *  creation data (creationHash).

     *  @param signHandle Handle of the key that will sign the attestation block
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param objectHandle The object associated with the creation data
     *         Auth Index: None
     *  @param qualifyingData User-provided qualifying data
     *  @param creationHash Hash of the creation data produced by TPM2_Create() or TPM2_CreatePrimary()
     *  @param inScheme Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
     *         One of: TPMS_SIG_SCHEME_RSASSA, TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA,
     *         TPMS_SIG_SCHEME_ECDAA, TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR,
     *         TPMS_SCHEME_HMAC, TPMS_SCHEME_HASH, TPMS_NULL_SIG_SCHEME.
     *  @param creationTicket Ticket produced by TPM2_Create() or TPM2_CreatePrimary()
     *  @return certifyInfo - The structure that was signed<br>
     *          signature - The signature over certifyInfo
     */
    public CertifyCreationResponse CertifyCreation(TPM_HANDLE signHandle, TPM_HANDLE objectHandle, byte[] qualifyingData, byte[] creationHash, TPMU_SIG_SCHEME inScheme, TPMT_TK_CREATION creationTicket)
    {
        TPM2_CertifyCreation_REQUEST req = new TPM2_CertifyCreation_REQUEST(signHandle, objectHandle, qualifyingData, creationHash, inScheme, creationTicket);
        CertifyCreationResponse resp = new CertifyCreationResponse();
        DispatchCommand(TPM_CC.CertifyCreation, req, resp);
        return resp;
    }

    /** This command is used to quote PCR values.

     *  @param signHandle Handle of key that will perform signature
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param qualifyingData Data supplied by the caller
     *  @param inScheme Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
     *         One of: TPMS_SIG_SCHEME_RSASSA, TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA,
     *         TPMS_SIG_SCHEME_ECDAA, TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR,
     *         TPMS_SCHEME_HMAC, TPMS_SCHEME_HASH, TPMS_NULL_SIG_SCHEME.
     *  @param PCRselect PCR set to quote
     *  @return quoted - The quoted information<br>
     *          signature - The signature over quoted
     */
    public QuoteResponse Quote(TPM_HANDLE signHandle, byte[] qualifyingData, TPMU_SIG_SCHEME inScheme, TPMS_PCR_SELECTION[] PCRselect)
    {
        TPM2_Quote_REQUEST req = new TPM2_Quote_REQUEST(signHandle, qualifyingData, inScheme, PCRselect);
        QuoteResponse resp = new QuoteResponse();
        DispatchCommand(TPM_CC.Quote, req, resp);
        return resp;
    }

    /** This command returns a digital signature of the audit session digest.

     *  @param privacyAdminHandle Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param signHandle Handle of the signing key
     *         Auth Index: 2
     *         Auth Role: USER
     *  @param sessionHandle Handle of the audit session
     *         Auth Index: None
     *  @param qualifyingData User-provided qualifying data may be zero-length
     *  @param inScheme Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
     *         One of: TPMS_SIG_SCHEME_RSASSA, TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA,
     *         TPMS_SIG_SCHEME_ECDAA, TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR,
     *         TPMS_SCHEME_HMAC, TPMS_SCHEME_HASH, TPMS_NULL_SIG_SCHEME.
     *  @return auditInfo - The audit information that was signed<br>
     *          signature - The signature over auditInfo
     */
    public GetSessionAuditDigestResponse GetSessionAuditDigest(TPM_HANDLE privacyAdminHandle, TPM_HANDLE signHandle, TPM_HANDLE sessionHandle, byte[] qualifyingData, TPMU_SIG_SCHEME inScheme)
    {
        TPM2_GetSessionAuditDigest_REQUEST req = new TPM2_GetSessionAuditDigest_REQUEST(privacyAdminHandle, signHandle, sessionHandle, qualifyingData, inScheme);
        GetSessionAuditDigestResponse resp = new GetSessionAuditDigestResponse();
        DispatchCommand(TPM_CC.GetSessionAuditDigest, req, resp);
        return resp;
    }

    /** This command returns the current value of the command audit digest, a digest of the
     *  commands being audited, and the audit hash algorithm. These values are placed in an
     *  attestation structure and signed with the key referenced by signHandle.

     *  @param privacyHandle Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param signHandle The handle of the signing key
     *         Auth Index: 2
     *         Auth Role: USER
     *  @param qualifyingData Other data to associate with this audit digest
     *  @param inScheme Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
     *         One of: TPMS_SIG_SCHEME_RSASSA, TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA,
     *         TPMS_SIG_SCHEME_ECDAA, TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR,
     *         TPMS_SCHEME_HMAC, TPMS_SCHEME_HASH, TPMS_NULL_SIG_SCHEME.
     *  @return auditInfo - The auditInfo that was signed<br>
     *          signature - The signature over auditInfo
     */
    public GetCommandAuditDigestResponse GetCommandAuditDigest(TPM_HANDLE privacyHandle, TPM_HANDLE signHandle, byte[] qualifyingData, TPMU_SIG_SCHEME inScheme)
    {
        TPM2_GetCommandAuditDigest_REQUEST req = new TPM2_GetCommandAuditDigest_REQUEST(privacyHandle, signHandle, qualifyingData, inScheme);
        GetCommandAuditDigestResponse resp = new GetCommandAuditDigestResponse();
        DispatchCommand(TPM_CC.GetCommandAuditDigest, req, resp);
        return resp;
    }

    /** This command returns the current values of Time and Clock.

     *  @param privacyAdminHandle Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param signHandle The keyHandle identifier of a loaded key that can perform digital signatures
     *         Auth Index: 2
     *         Auth Role: USER
     *  @param qualifyingData Data to tick stamp
     *  @param inScheme Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
     *         One of: TPMS_SIG_SCHEME_RSASSA, TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA,
     *         TPMS_SIG_SCHEME_ECDAA, TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR,
     *         TPMS_SCHEME_HMAC, TPMS_SCHEME_HASH, TPMS_NULL_SIG_SCHEME.
     *  @return timeInfo - Standard TPM-generated attestation block<br>
     *          signature - The signature over timeInfo
     */
    public GetTimeResponse GetTime(TPM_HANDLE privacyAdminHandle, TPM_HANDLE signHandle, byte[] qualifyingData, TPMU_SIG_SCHEME inScheme)
    {
        TPM2_GetTime_REQUEST req = new TPM2_GetTime_REQUEST(privacyAdminHandle, signHandle, qualifyingData, inScheme);
        GetTimeResponse resp = new GetTimeResponse();
        DispatchCommand(TPM_CC.GetTime, req, resp);
        return resp;
    }

    /** The purpose of this command is to generate an X.509 certificate that proves an object
     *  with a specific public key and attributes is loaded in the TPM. In contrast to
     *  TPM2_Certify, which uses a TCG-defined data structure to convey attestation
     *  information, TPM2_CertifyX509 encodes the attestation information in a DER-encoded
     *  X.509 certificate that is compliant with RFC5280 Internet X.509 Public Key
     *  Infrastructure Certificate and Certificate Revocation List (CRL) Profile.

     *  @param objectHandle Handle of the object to be certified
     *         Auth Index: 1
     *         Auth Role: ADMIN
     *  @param signHandle Handle of the key used to sign the attestation structure
     *         Auth Index: 2
     *         Auth Role: USER
     *  @param reserved Shall be an Empty Buffer
     *  @param inScheme Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
     *         One of: TPMS_SIG_SCHEME_RSASSA, TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA,
     *         TPMS_SIG_SCHEME_ECDAA, TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR,
     *         TPMS_SCHEME_HMAC, TPMS_SCHEME_HASH, TPMS_NULL_SIG_SCHEME.
     *  @param partialCertificate A DER encoded partial certificate
     *  @return addedToCertificate - A DER encoded SEQUENCE containing the DER encoded fields
     *                               added to partialCertificate to make it a complete RFC5280
     *                               TBSCertificate.<br>
     *          tbsDigest - The digest that was signed<br>
     *          signature - The signature over tbsDigest
     */
    public CertifyX509Response CertifyX509(TPM_HANDLE objectHandle, TPM_HANDLE signHandle, byte[] reserved, TPMU_SIG_SCHEME inScheme, byte[] partialCertificate)
    {
        TPM2_CertifyX509_REQUEST req = new TPM2_CertifyX509_REQUEST(objectHandle, signHandle, reserved, inScheme, partialCertificate);
        CertifyX509Response resp = new CertifyX509Response();
        DispatchCommand(TPM_CC.CertifyX509, req, resp);
        return resp;
    }

    /** TPM2_Commit() performs the first part of an ECC anonymous signing operation. The TPM
     *  will perform the point multiplications on the provided points and return intermediate
     *  signing values. The signHandle parameter shall refer to an ECC key and the signing
     *  scheme must be anonymous (TPM_RC_SCHEME).

     *  @param signHandle Handle of the key that will be used in the signing operation
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param P1 A point (M) on the curve used by signHandle
     *  @param s2 Octet array used to derive x-coordinate of a base point
     *  @param y2 Y coordinate of the point associated with s2
     *  @return K - ECC point K [ds](x2, y2)<br>
     *          L - ECC point L [r](x2, y2)<br>
     *          E - ECC point E [r]P1<br>
     *          counter - Least-significant 16 bits of commitCount
     */
    public CommitResponse Commit(TPM_HANDLE signHandle, TPMS_ECC_POINT P1, byte[] s2, byte[] y2)
    {
        TPM2_Commit_REQUEST req = new TPM2_Commit_REQUEST(signHandle, P1, s2, y2);
        CommitResponse resp = new CommitResponse();
        DispatchCommand(TPM_CC.Commit, req, resp);
        return resp;
    }

    /** TPM2_EC_Ephemeral() creates an ephemeral key for use in a two-phase key exchange protocol.

     *  @param curveID The curve for the computed ephemeral point
     *  @return Q - Ephemeral public key Q [r]G<br>
     *          counter - Least-significant 16 bits of commitCount
     */
    public EC_EphemeralResponse EC_Ephemeral(TPM_ECC_CURVE curveID)
    {
        TPM2_EC_Ephemeral_REQUEST req = new TPM2_EC_Ephemeral_REQUEST(curveID);
        EC_EphemeralResponse resp = new EC_EphemeralResponse();
        DispatchCommand(TPM_CC.EC_Ephemeral, req, resp);
        return resp;
    }

    /** This command uses loaded keys to validate a signature on a message with the message
     *  digest passed to the TPM.

     *  @param keyHandle Handle of public key that will be used in the validation
     *         Auth Index: None
     *  @param digest Digest of the signed message
     *  @param signature Signature to be tested
     *         One of: TPMS_SIGNATURE_RSASSA, TPMS_SIGNATURE_RSAPSS, TPMS_SIGNATURE_ECDSA,
     *         TPMS_SIGNATURE_ECDAA, TPMS_SIGNATURE_SM2, TPMS_SIGNATURE_ECSCHNORR, TPMT_HA,
     *         TPMS_SCHEME_HASH, TPMS_NULL_SIGNATURE.
     *  @return validation - This ticket is produced by TPM2_VerifySignature(). This formulation
     *                       is used for multiple ticket uses. The ticket provides evidence that
     *                       the TPM has validated that a digest was signed by a key with the Name
     *                       of keyName. The ticket is computed by
     */
    public TPMT_TK_VERIFIED VerifySignature(TPM_HANDLE keyHandle, byte[] digest, TPMU_SIGNATURE signature)
    {
        TPM2_VerifySignature_REQUEST req = new TPM2_VerifySignature_REQUEST(keyHandle, digest, signature);
        VerifySignatureResponse resp = new VerifySignatureResponse();
        DispatchCommand(TPM_CC.VerifySignature, req, resp);
        return resp.validation;
    }

    /** This command causes the TPM to sign an externally provided hash with the specified
     *  symmetric or asymmetric signing key.

     *  @param keyHandle Handle of key that will perform signing
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param digest Digest to be signed
     *  @param inScheme Signing scheme to use if the scheme for keyHandle is TPM_ALG_NULL
     *         One of: TPMS_SIG_SCHEME_RSASSA, TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA,
     *         TPMS_SIG_SCHEME_ECDAA, TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR,
     *         TPMS_SCHEME_HMAC, TPMS_SCHEME_HASH, TPMS_NULL_SIG_SCHEME.
     *  @param validation Proof that digest was created by the TPM
     *         If keyHandle is not a restricted signing key, then this may be a NULL Ticket with
     *         tag = TPM_ST_CHECKHASH.
     *  @return signature - The signature
     */
    public TPMU_SIGNATURE Sign(TPM_HANDLE keyHandle, byte[] digest, TPMU_SIG_SCHEME inScheme, TPMT_TK_HASHCHECK validation)
    {
        TPM2_Sign_REQUEST req = new TPM2_Sign_REQUEST(keyHandle, digest, inScheme, validation);
        SignResponse resp = new SignResponse();
        DispatchCommand(TPM_CC.Sign, req, resp);
        return resp.signature;
    }

    /** This command may be used by the Privacy Administrator or platform to change the audit
     *  status of a command or to set the hash algorithm used for the audit digest, but not
     *  both at the same time.

     *  @param auth TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param auditAlg Hash algorithm for the audit digest; if TPM_ALG_NULL, then the hash is
     *  not
     *         changed
     *  @param setList List of commands that will be added to those that will be audited
     *  @param clearList List of commands that will no longer be audited
     */
    public void SetCommandCodeAuditStatus(TPM_HANDLE auth, TPM_ALG_ID auditAlg, TPM_CC[] setList, TPM_CC[] clearList)
    {
        TPM2_SetCommandCodeAuditStatus_REQUEST req = new TPM2_SetCommandCodeAuditStatus_REQUEST(auth, auditAlg, setList, clearList);
        DispatchCommand(TPM_CC.SetCommandCodeAuditStatus, req, null);
        return;
    }

    /** This command is used to cause an update to the indicated PCR. The digests parameter
     *  contains one or more tagged digest values identified by an algorithm ID. For each
     *  digest, the PCR associated with pcrHandle is Extended into the bank identified by the
     *  tag (hashAlg).

     *  @param pcrHandle Handle of the PCR
     *         Auth Handle: 1
     *         Auth Role: USER
     *  @param digests List of tagged digest values to be extended
     */
    public void PCR_Extend(TPM_HANDLE pcrHandle, TPMT_HA[] digests)
    {
        TPM2_PCR_Extend_REQUEST req = new TPM2_PCR_Extend_REQUEST(pcrHandle, digests);
        DispatchCommand(TPM_CC.PCR_Extend, req, null);
        return;
    }

    /** This command is used to cause an update to the indicated PCR.

     *  @param pcrHandle Handle of the PCR
     *         Auth Handle: 1
     *         Auth Role: USER
     *  @param eventData Event data in sized buffer
     *  @return digests - Table 80 shows the basic hash-agile structure used in this
     *                    specification. To handle hash agility, this structure uses the hashAlg
     *                    parameter to indicate the algorithm used to compute the digest and, by
     *                    implication, the size of the digest.
     */
    public TPMT_HA[] PCR_Event(TPM_HANDLE pcrHandle, byte[] eventData)
    {
        TPM2_PCR_Event_REQUEST req = new TPM2_PCR_Event_REQUEST(pcrHandle, eventData);
        PCR_EventResponse resp = new PCR_EventResponse();
        DispatchCommand(TPM_CC.PCR_Event, req, resp);
        return resp.digests;
    }

    /** This command returns the values of all PCR specified in pcrSelectionIn.

     *  @param pcrSelectionIn The selection of PCR to read
     *  @return pcrUpdateCounter - The current value of the PCR update counter<br>
     *          pcrSelectionOut - The PCR in the returned list<br>
     *          pcrValues - The contents of the PCR indicated in pcrSelectOut-˃ pcrSelection[]
     *  as
     *                      tagged digests
     */
    public PCR_ReadResponse PCR_Read(TPMS_PCR_SELECTION[] pcrSelectionIn)
    {
        TPM2_PCR_Read_REQUEST req = new TPM2_PCR_Read_REQUEST(pcrSelectionIn);
        PCR_ReadResponse resp = new PCR_ReadResponse();
        DispatchCommand(TPM_CC.PCR_Read, req, resp);
        return resp;
    }

    /** This command is used to set the desired PCR allocation of PCR and algorithms. This
     *  command requires Platform Authorization.

     *  @param authHandle TPM_RH_PLATFORM+{PP}
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param pcrAllocation The requested allocation
     *  @return allocationSuccess - YES if the allocation succeeded<br>
     *          maxPCR - Maximum number of PCR that may be in a bank<br>
     *          sizeNeeded - Number of octets required to satisfy the request<br>
     *          sizeAvailable - Number of octets available. Computed before the allocation.
     */
    public PCR_AllocateResponse PCR_Allocate(TPM_HANDLE authHandle, TPMS_PCR_SELECTION[] pcrAllocation)
    {
        TPM2_PCR_Allocate_REQUEST req = new TPM2_PCR_Allocate_REQUEST(authHandle, pcrAllocation);
        PCR_AllocateResponse resp = new PCR_AllocateResponse();
        DispatchCommand(TPM_CC.PCR_Allocate, req, resp);
        return resp;
    }

    /** This command is used to associate a policy with a PCR or group of PCR. The policy
     *  determines the conditions under which a PCR may be extended or reset.

     *  @param authHandle TPM_RH_PLATFORM+{PP}
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param authPolicy The desired authPolicy
     *  @param hashAlg The hash algorithm of the policy
     *  @param pcrNum The PCR for which the policy is to be set
     */
    public void PCR_SetAuthPolicy(TPM_HANDLE authHandle, byte[] authPolicy, TPM_ALG_ID hashAlg, TPM_HANDLE pcrNum)
    {
        TPM2_PCR_SetAuthPolicy_REQUEST req = new TPM2_PCR_SetAuthPolicy_REQUEST(authHandle, authPolicy, hashAlg, pcrNum);
        DispatchCommand(TPM_CC.PCR_SetAuthPolicy, req, null);
        return;
    }

    /** This command changes the authValue of a PCR or group of PCR.

     *  @param pcrHandle Handle for a PCR that may have an authorization value set
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param auth The desired authorization value
     */
    public void PCR_SetAuthValue(TPM_HANDLE pcrHandle, byte[] auth)
    {
        TPM2_PCR_SetAuthValue_REQUEST req = new TPM2_PCR_SetAuthValue_REQUEST(pcrHandle, auth);
        DispatchCommand(TPM_CC.PCR_SetAuthValue, req, null);
        return;
    }

    /** If the attribute of a PCR allows the PCR to be reset and proper authorization is
     *  provided, then this command may be used to set the PCR in all banks to zero. The
     *  attributes of the PCR may restrict the locality that can perform the reset operation.

     *  @param pcrHandle The PCR to reset
     *         Auth Index: 1
     *         Auth Role: USER
     */
    public void PCR_Reset(TPM_HANDLE pcrHandle)
    {
        TPM2_PCR_Reset_REQUEST req = new TPM2_PCR_Reset_REQUEST(pcrHandle);
        DispatchCommand(TPM_CC.PCR_Reset, req, null);
        return;
    }

    /** This command includes a signed authorization in a policy. The command ties the policy
     *  to a signing key by including the Name of the signing key in the policyDigest

     *  @param authObject Handle for a key that will validate the signature
     *         Auth Index: None
     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param nonceTPM The policy nonce for the session
     *         This can be the Empty Buffer.
     *  @param cpHashA Digest of the command parameters to which this authorization is limited
     *         This is not the cpHash for this command but the cpHash for the command to which
     *         this policy session will be applied. If it is not limited, the parameter will be
     *         the Empty Buffer.
     *  @param policyRef A reference to a policy relating to the authorization may be the
     *  Empty Buffer
     *         Size is limited to be no larger than the nonce size supported on the TPM.
     *  @param expiration Time when authorization will expire, measured in seconds from the time
     *         that nonceTPM was generated
     *         If expiration is non-negative, a NULL Ticket is returned. See 23.2.5.
     *  @param auth Signed authorization (not optional)
     *         One of: TPMS_SIGNATURE_RSASSA, TPMS_SIGNATURE_RSAPSS, TPMS_SIGNATURE_ECDSA,
     *         TPMS_SIGNATURE_ECDAA, TPMS_SIGNATURE_SM2, TPMS_SIGNATURE_ECSCHNORR, TPMT_HA,
     *         TPMS_SCHEME_HASH, TPMS_NULL_SIGNATURE.
     *  @return timeout - Implementation-specific time value, used to indicate to the TPM when
     *  the
     *                    ticket expires
     *                    NOTE If policyTicket is a NULL Ticket, then this shall be the Empty Buffer.<br>
     *          policyTicket - Produced if the command succeeds and expiration in the command was
     *                         non-zero; this ticket will use the TPMT_ST_AUTH_SIGNED structure
     *                         tag. See 23.2.5
     */
    public PolicySignedResponse PolicySigned(TPM_HANDLE authObject, TPM_HANDLE policySession, byte[] nonceTPM, byte[] cpHashA, byte[] policyRef, int expiration, TPMU_SIGNATURE auth)
    {
        TPM2_PolicySigned_REQUEST req = new TPM2_PolicySigned_REQUEST(authObject, policySession, nonceTPM, cpHashA, policyRef, expiration, auth);
        PolicySignedResponse resp = new PolicySignedResponse();
        DispatchCommand(TPM_CC.PolicySigned, req, resp);
        return resp;
    }

    /** This command includes a secret-based authorization to a policy. The caller proves
     *  knowledge of the secret value using an authorization session using the authValue
     *  associated with authHandle. A password session, an HMAC session, or a policy session
     *  containing TPM2_PolicyAuthValue() or TPM2_PolicyPassword() will satisfy this requirement.

     *  @param authHandle Handle for an entity providing the authorization
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param nonceTPM The policy nonce for the session
     *         This can be the Empty Buffer.
     *  @param cpHashA Digest of the command parameters to which this authorization is limited
     *         This not the cpHash for this command but the cpHash for the command to which this
     *         policy session will be applied. If it is not limited, the parameter will be the
     *         Empty Buffer.
     *  @param policyRef A reference to a policy relating to the authorization may be the
     *  Empty Buffer
     *         Size is limited to be no larger than the nonce size supported on the TPM.
     *  @param expiration Time when authorization will expire, measured in seconds from the time
     *         that nonceTPM was generated
     *         If expiration is non-negative, a NULL Ticket is returned. See 23.2.5.
     *  @return timeout - Implementation-specific time value used to indicate to the TPM when the
     *                    ticket expires<br>
     *          policyTicket - Produced if the command succeeds and expiration in the command was
     *                         non-zero ( See 23.2.5). This ticket will use the
     *                         TPMT_ST_AUTH_SECRET structure tag
     */
    public PolicySecretResponse PolicySecret(TPM_HANDLE authHandle, TPM_HANDLE policySession, byte[] nonceTPM, byte[] cpHashA, byte[] policyRef, int expiration)
    {
        TPM2_PolicySecret_REQUEST req = new TPM2_PolicySecret_REQUEST(authHandle, policySession, nonceTPM, cpHashA, policyRef, expiration);
        PolicySecretResponse resp = new PolicySecretResponse();
        DispatchCommand(TPM_CC.PolicySecret, req, resp);
        return resp;
    }

    /** This command is similar to TPM2_PolicySigned() except that it takes a ticket instead
     *  of a signed authorization. The ticket represents a validated authorization that had an
     *  expiration time associated with it.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param timeout Time when authorization will expire
     *         The contents are TPM specific. This shall be the value returned when ticket was
     *  produced.
     *  @param cpHashA Digest of the command parameters to which this authorization is limited
     *         If it is not limited, the parameter will be the Empty Buffer.
     *  @param policyRef Reference to a qualifier for the policy may be the Empty Buffer
     *  @param authName Name of the object that provided the authorization
     *  @param ticket An authorization ticket returned by the TPM in response to a
     *         TPM2_PolicySigned() or TPM2_PolicySecret()
     */
    public void PolicyTicket(TPM_HANDLE policySession, byte[] timeout, byte[] cpHashA, byte[] policyRef, byte[] authName, TPMT_TK_AUTH ticket)
    {
        TPM2_PolicyTicket_REQUEST req = new TPM2_PolicyTicket_REQUEST(policySession, timeout, cpHashA, policyRef, authName, ticket);
        DispatchCommand(TPM_CC.PolicyTicket, req, null);
        return;
    }

    /** This command allows options in authorizations without requiring that the TPM evaluate
     *  all of the options. If a policy may be satisfied by different sets of conditions, the
     *  TPM need only evaluate one set that satisfies the policy. This command will indicate
     *  that one of the required sets of conditions has been satisfied.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param pHashList The list of hashes to check for a match
     */
    public void PolicyOR(TPM_HANDLE policySession, TPM2B_DIGEST[] pHashList)
    {
        TPM2_PolicyOR_REQUEST req = new TPM2_PolicyOR_REQUEST(policySession, pHashList);
        DispatchCommand(TPM_CC.PolicyOR, req, null);
        return;
    }

    /** This command is used to cause conditional gating of a policy based on PCR. This
     *  command together with TPM2_PolicyOR() allows one group of authorizations to occur when
     *  PCR are in one state and a different set of authorizations when the PCR are in a
     *  different state.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param pcrDigest Expected digest value of the selected PCR using the hash algorithm of
     *  the
     *         session; may be zero length
     *  @param pcrs The PCR to include in the check digest
     */
    public void PolicyPCR(TPM_HANDLE policySession, byte[] pcrDigest, TPMS_PCR_SELECTION[] pcrs)
    {
        TPM2_PolicyPCR_REQUEST req = new TPM2_PolicyPCR_REQUEST(policySession, pcrDigest, pcrs);
        DispatchCommand(TPM_CC.PolicyPCR, req, null);
        return;
    }

    /** This command indicates that the authorization will be limited to a specific locality.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param locality The allowed localities for the policy
     */
    public void PolicyLocality(TPM_HANDLE policySession, TPMA_LOCALITY locality)
    {
        TPM2_PolicyLocality_REQUEST req = new TPM2_PolicyLocality_REQUEST(policySession, locality);
        DispatchCommand(TPM_CC.PolicyLocality, req, null);
        return;
    }

    /** This command is used to cause conditional gating of a policy based on the contents of
     *  an NV Index. It is an immediate assertion. The NV index is validated during the
     *  TPM2_PolicyNV() command, not when the session is used for authorization.

     *  @param authHandle Handle indicating the source of the authorization value
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param nvIndex The NV Index of the area to read
     *         Auth Index: None
     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param operandB The second operand
     *  @param offset The octet offset in the NV Index for the start of operand A
     *  @param operation The comparison to make
     */
    public void PolicyNV(TPM_HANDLE authHandle, TPM_HANDLE nvIndex, TPM_HANDLE policySession, byte[] operandB, int offset, TPM_EO operation)
    {
        TPM2_PolicyNV_REQUEST req = new TPM2_PolicyNV_REQUEST(authHandle, nvIndex, policySession, operandB, offset, operation);
        DispatchCommand(TPM_CC.PolicyNV, req, null);
        return;
    }

    /** This command is used to cause conditional gating of a policy based on the contents of
     *  the TPMS_TIME_INFO structure.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param operandB The second operand
     *  @param offset The octet offset in the TPMS_TIME_INFO structure for the start of
     *  operand A
     *  @param operation The comparison to make
     */
    public void PolicyCounterTimer(TPM_HANDLE policySession, byte[] operandB, int offset, TPM_EO operation)
    {
        TPM2_PolicyCounterTimer_REQUEST req = new TPM2_PolicyCounterTimer_REQUEST(policySession, operandB, offset, operation);
        DispatchCommand(TPM_CC.PolicyCounterTimer, req, null);
        return;
    }

    /** This command indicates that the authorization will be limited to a specific command code.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param code The allowed commandCode
     */
    public void PolicyCommandCode(TPM_HANDLE policySession, TPM_CC code)
    {
        TPM2_PolicyCommandCode_REQUEST req = new TPM2_PolicyCommandCode_REQUEST(policySession, code);
        DispatchCommand(TPM_CC.PolicyCommandCode, req, null);
        return;
    }

    /** This command indicates that physical presence will need to be asserted at the time the
     *  authorization is performed.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     */
    public void PolicyPhysicalPresence(TPM_HANDLE policySession)
    {
        TPM2_PolicyPhysicalPresence_REQUEST req = new TPM2_PolicyPhysicalPresence_REQUEST(policySession);
        DispatchCommand(TPM_CC.PolicyPhysicalPresence, req, null);
        return;
    }

    /** This command is used to allow a policy to be bound to a specific command and command parameters.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param cpHashA The cpHash added to the policy
     */
    public void PolicyCpHash(TPM_HANDLE policySession, byte[] cpHashA)
    {
        TPM2_PolicyCpHash_REQUEST req = new TPM2_PolicyCpHash_REQUEST(policySession, cpHashA);
        DispatchCommand(TPM_CC.PolicyCpHash, req, null);
        return;
    }

    /** This command allows a policy to be bound to a specific set of TPM entities without
     *  being bound to the parameters of the command. This is most useful for commands such as
     *  TPM2_Duplicate() and for TPM2_PCR_Event() when the referenced PCR requires a policy.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param nameHash The digest to be added to the policy
     */
    public void PolicyNameHash(TPM_HANDLE policySession, byte[] nameHash)
    {
        TPM2_PolicyNameHash_REQUEST req = new TPM2_PolicyNameHash_REQUEST(policySession, nameHash);
        DispatchCommand(TPM_CC.PolicyNameHash, req, null);
        return;
    }

    /** This command allows qualification of duplication to allow duplication to a selected
     *  new parent.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param objectName The Name of the object to be duplicated
     *  @param newParentName The Name of the new parent
     *  @param includeObject If YES, the objectName will be included in the value in
     *         policySessionpolicyDigest
     */
    public void PolicyDuplicationSelect(TPM_HANDLE policySession, byte[] objectName, byte[] newParentName, byte includeObject)
    {
        TPM2_PolicyDuplicationSelect_REQUEST req = new TPM2_PolicyDuplicationSelect_REQUEST(policySession, objectName, newParentName, includeObject);
        DispatchCommand(TPM_CC.PolicyDuplicationSelect, req, null);
        return;
    }

    /** This command allows policies to change. If a policy were static, then it would be
     *  difficult to add users to a policy. This command lets a policy authority sign a new
     *  policy so that it may be used in an existing policy.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param approvedPolicy Digest of the policy being approved
     *  @param policyRef A policy qualifier
     *  @param keySign Name of a key that can sign a policy addition
     *  @param checkTicket Ticket validating that approvedPolicy and policyRef were signed by keySign
     */
    public void PolicyAuthorize(TPM_HANDLE policySession, byte[] approvedPolicy, byte[] policyRef, byte[] keySign, TPMT_TK_VERIFIED checkTicket)
    {
        TPM2_PolicyAuthorize_REQUEST req = new TPM2_PolicyAuthorize_REQUEST(policySession, approvedPolicy, policyRef, keySign, checkTicket);
        DispatchCommand(TPM_CC.PolicyAuthorize, req, null);
        return;
    }

    /** This command allows a policy to be bound to the authorization value of the authorized entity.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     */
    public void PolicyAuthValue(TPM_HANDLE policySession)
    {
        TPM2_PolicyAuthValue_REQUEST req = new TPM2_PolicyAuthValue_REQUEST(policySession);
        DispatchCommand(TPM_CC.PolicyAuthValue, req, null);
        return;
    }

    /** This command allows a policy to be bound to the authorization value of the authorized object.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     */
    public void PolicyPassword(TPM_HANDLE policySession)
    {
        TPM2_PolicyPassword_REQUEST req = new TPM2_PolicyPassword_REQUEST(policySession);
        DispatchCommand(TPM_CC.PolicyPassword, req, null);
        return;
    }

    /** This command returns the current policyDigest of the session. This command allows the
     *  TPM to be used to perform the actions required to pre-compute the authPolicy for an object.

     *  @param policySession Handle for the policy session
     *         Auth Index: None
     *  @return policyDigest - The current value of the policySessionpolicyDigest
     */
    public byte[] PolicyGetDigest(TPM_HANDLE policySession)
    {
        TPM2_PolicyGetDigest_REQUEST req = new TPM2_PolicyGetDigest_REQUEST(policySession);
        PolicyGetDigestResponse resp = new PolicyGetDigestResponse();
        DispatchCommand(TPM_CC.PolicyGetDigest, req, resp);
        return resp.policyDigest;
    }

    /** This command allows a policy to be bound to the TPMA_NV_WRITTEN attributes. This is a
     *  deferred assertion. Values are stored in the policy session context and checked when
     *  the policy is used for authorization.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param writtenSet YES if NV Index is required to have been written
     *         NO if NV Index is required not to have been written
     */
    public void PolicyNvWritten(TPM_HANDLE policySession, byte writtenSet)
    {
        TPM2_PolicyNvWritten_REQUEST req = new TPM2_PolicyNvWritten_REQUEST(policySession, writtenSet);
        DispatchCommand(TPM_CC.PolicyNvWritten, req, null);
        return;
    }

    /** This command allows a policy to be bound to a specific creation template. This is most
     *  useful for an object creation command such as TPM2_Create(), TPM2_CreatePrimary(), or
     *  TPM2_CreateLoaded().

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param templateHash The digest to be added to the policy
     */
    public void PolicyTemplate(TPM_HANDLE policySession, byte[] templateHash)
    {
        TPM2_PolicyTemplate_REQUEST req = new TPM2_PolicyTemplate_REQUEST(policySession, templateHash);
        DispatchCommand(TPM_CC.PolicyTemplate, req, null);
        return;
    }

    /** This command provides a capability that is the equivalent of a revocable policy. With
     *  TPM2_PolicyAuthorize(), the authorization ticket never expires, so the authorization
     *  may not be withdrawn. With this command, the approved policy is kept in an NV Index
     *  location so that the policy may be changed as needed to render the old policy unusable.

     *  @param authHandle Handle indicating the source of the authorization value
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param nvIndex The NV Index of the area to read
     *         Auth Index: None
     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     */
    public void PolicyAuthorizeNV(TPM_HANDLE authHandle, TPM_HANDLE nvIndex, TPM_HANDLE policySession)
    {
        TPM2_PolicyAuthorizeNV_REQUEST req = new TPM2_PolicyAuthorizeNV_REQUEST(authHandle, nvIndex, policySession);
        DispatchCommand(TPM_CC.PolicyAuthorizeNV, req, null);
        return;
    }

    /** This command is used to create a Primary Object under one of the Primary Seeds or a
     *  Temporary Object under TPM_RH_NULL. The command uses a TPM2B_PUBLIC as a template for
     *  the object to be created. The size of the unique field shall not be checked for
     *  consistency with the other object parameters. The command will create and load a
     *  Primary Object. The sensitive area is not returned.

     *  @param primaryHandle TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param inSensitive The sensitive data, see TPM 2.0 Part 1 Sensitive Values
     *  @param inPublic The public template
     *  @param outsideInfo Data that will be included in the creation data for this object to
     *         provide permanent, verifiable linkage between this object and some object owner
     *  data
     *  @param creationPCR PCR that will be used in creation data
     *  @return handle - Handle of type TPM_HT_TRANSIENT for created Primary Object<br>
     *          outPublic - The public portion of the created object<br>
     *          creationData - Contains a TPMT_CREATION_DATA<br>
     *          creationHash - Digest of creationData using nameAlg of outPublic<br>
     *          creationTicket - Ticket used by TPM2_CertifyCreation() to validate that the
     *                           creation data was produced by the TPM<br>
     *          name - The name of the created object
     */
    public CreatePrimaryResponse CreatePrimary(TPM_HANDLE primaryHandle, TPMS_SENSITIVE_CREATE inSensitive, TPMT_PUBLIC inPublic, byte[] outsideInfo, TPMS_PCR_SELECTION[] creationPCR)
    {
        TPM2_CreatePrimary_REQUEST req = new TPM2_CreatePrimary_REQUEST(primaryHandle, inSensitive, inPublic, outsideInfo, creationPCR);
        CreatePrimaryResponse resp = new CreatePrimaryResponse();
        DispatchCommand(TPM_CC.CreatePrimary, req, resp);
        return resp;
    }

    /** This command enables and disables use of a hierarchy and its associated NV storage.
     *  The command allows phEnable, phEnableNV, shEnable, and ehEnable to be changed when the
     *  proper authorization is provided.

     *  @param authHandle TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param enable The enable being modified
     *         TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM, or TPM_RH_PLATFORM_NV
     *  @param state YES if the enable should be SET, NO if the enable should be CLEAR
     */
    public void HierarchyControl(TPM_HANDLE authHandle, TPM_HANDLE enable, byte state)
    {
        TPM2_HierarchyControl_REQUEST req = new TPM2_HierarchyControl_REQUEST(authHandle, enable, state);
        DispatchCommand(TPM_CC.HierarchyControl, req, null);
        return;
    }

    /** This command allows setting of the authorization policy for the lockout
     *  (lockoutPolicy), the platform hierarchy (platformPolicy), the storage hierarchy
     *  (ownerPolicy), and the endorsement hierarchy (endorsementPolicy). On TPMs implementing
     *  Authenticated Countdown Timers (ACT), this command may also be used to set the
     *  authorization policy for an ACT.

     *  @param authHandle TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPMI_RH_ACT or
     *         TPM_RH_PLATFORM+{PP}
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param authPolicy An authorization policy digest; may be the Empty Buffer
     *         If hashAlg is TPM_ALG_NULL, then this shall be an Empty Buffer.
     *  @param hashAlg The hash algorithm to use for the policy
     *         If the authPolicy is an Empty Buffer, then this field shall be TPM_ALG_NULL.
     */
    public void SetPrimaryPolicy(TPM_HANDLE authHandle, byte[] authPolicy, TPM_ALG_ID hashAlg)
    {
        TPM2_SetPrimaryPolicy_REQUEST req = new TPM2_SetPrimaryPolicy_REQUEST(authHandle, authPolicy, hashAlg);
        DispatchCommand(TPM_CC.SetPrimaryPolicy, req, null);
        return;
    }

    /** This replaces the current platform primary seed (PPS) with a value from the RNG and
     *  sets platformPolicy to the default initialization value (the Empty Buffer).

     *  @param authHandle TPM_RH_PLATFORM+{PP}
     *         Auth Index: 1
     *         Auth Role: USER
     */
    public void ChangePPS(TPM_HANDLE authHandle)
    {
        TPM2_ChangePPS_REQUEST req = new TPM2_ChangePPS_REQUEST(authHandle);
        DispatchCommand(TPM_CC.ChangePPS, req, null);
        return;
    }

    /** This replaces the current endorsement primary seed (EPS) with a value from the RNG and
     *  sets the Endorsement hierarchy controls to their default initialization values:
     *  ehEnable is SET, endorsementAuth and endorsementPolicy are both set to the Empty
     *  Buffer. It will flush any resident objects (transient or persistent) in the
     *  Endorsement hierarchy and not allow objects in the hierarchy associated with the
     *  previous EPS to be loaded.

     *  @param authHandle TPM_RH_PLATFORM+{PP}
     *         Auth Handle: 1
     *         Auth Role: USER
     */
    public void ChangeEPS(TPM_HANDLE authHandle)
    {
        TPM2_ChangeEPS_REQUEST req = new TPM2_ChangeEPS_REQUEST(authHandle);
        DispatchCommand(TPM_CC.ChangeEPS, req, null);
        return;
    }

    /** This command removes all TPM context associated with a specific Owner.

     *  @param authHandle TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
     *         Auth Handle: 1
     *         Auth Role: USER
     */
    public void Clear(TPM_HANDLE authHandle)
    {
        TPM2_Clear_REQUEST req = new TPM2_Clear_REQUEST(authHandle);
        DispatchCommand(TPM_CC.Clear, req, null);
        return;
    }

    /** TPM2_ClearControl() disables and enables the execution of TPM2_Clear().

     *  @param auth TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
     *         Auth Handle: 1
     *         Auth Role: USER
     *  @param disable YES if the disableOwnerClear flag is to be SET, NO if the flag is to be
     *  CLEAR.
     */
    public void ClearControl(TPM_HANDLE auth, byte disable)
    {
        TPM2_ClearControl_REQUEST req = new TPM2_ClearControl_REQUEST(auth, disable);
        DispatchCommand(TPM_CC.ClearControl, req, null);
        return;
    }

    /** This command allows the authorization secret for a hierarchy or lockout to be changed
     *  using the current authorization value as the command authorization.

     *  @param authHandle TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param newAuth New authorization value
     */
    public void HierarchyChangeAuth(TPM_HANDLE authHandle, byte[] newAuth)
    {
        TPM2_HierarchyChangeAuth_REQUEST req = new TPM2_HierarchyChangeAuth_REQUEST(authHandle, newAuth);
        DispatchCommand(TPM_CC.HierarchyChangeAuth, req, null);
        return;
    }

    /** This command cancels the effect of a TPM lockout due to a number of successive
     *  authorization failures. If this command is properly authorized, the lockout counter is
     *  set to zero.

     *  @param lockHandle TPM_RH_LOCKOUT
     *         Auth Index: 1
     *         Auth Role: USER
     */
    public void DictionaryAttackLockReset(TPM_HANDLE lockHandle)
    {
        TPM2_DictionaryAttackLockReset_REQUEST req = new TPM2_DictionaryAttackLockReset_REQUEST(lockHandle);
        DispatchCommand(TPM_CC.DictionaryAttackLockReset, req, null);
        return;
    }

    /** This command changes the lockout parameters.

     *  @param lockHandle TPM_RH_LOCKOUT
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param newMaxTries Count of authorization failures before the lockout is imposed
     *  @param newRecoveryTime Time in seconds before the authorization failure count is
     *         automatically decremented
     *         A value of zero indicates that DA protection is disabled.
     *  @param lockoutRecovery Time in seconds after a lockoutAuth failure before use of
     *         lockoutAuth is allowed
     *         A value of zero indicates that a reboot is required.
     */
    public void DictionaryAttackParameters(TPM_HANDLE lockHandle, int newMaxTries, int newRecoveryTime, int lockoutRecovery)
    {
        TPM2_DictionaryAttackParameters_REQUEST req = new TPM2_DictionaryAttackParameters_REQUEST(lockHandle, newMaxTries, newRecoveryTime, lockoutRecovery);
        DispatchCommand(TPM_CC.DictionaryAttackParameters, req, null);
        return;
    }

    /** This command is used to determine which commands require assertion of Physical
     *  Presence (PP) in addition to platformAuth/platformPolicy.

     *  @param auth TPM_RH_PLATFORM+PP
     *         Auth Index: 1
     *         Auth Role: USER + Physical Presence
     *  @param setList List of commands to be added to those that will require that Physical
     *         Presence be asserted
     *  @param clearList List of commands that will no longer require that Physical Presence
     *  be asserted
     */
    public void PP_Commands(TPM_HANDLE auth, TPM_CC[] setList, TPM_CC[] clearList)
    {
        TPM2_PP_Commands_REQUEST req = new TPM2_PP_Commands_REQUEST(auth, setList, clearList);
        DispatchCommand(TPM_CC.PP_Commands, req, null);
        return;
    }

    /** This command allows the platform to change the set of algorithms that are used by the
     *  TPM. The algorithmSet setting is a vendor-dependent value.

     *  @param authHandle TPM_RH_PLATFORM
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param algorithmSet A TPM vendor-dependent value indicating the algorithm set selection
     */
    public void SetAlgorithmSet(TPM_HANDLE authHandle, int algorithmSet)
    {
        TPM2_SetAlgorithmSet_REQUEST req = new TPM2_SetAlgorithmSet_REQUEST(authHandle, algorithmSet);
        DispatchCommand(TPM_CC.SetAlgorithmSet, req, null);
        return;
    }

    /** This command uses platformPolicy and a TPM Vendor Authorization Key to authorize a
     *  Field Upgrade Manifest.

     *  @param authorization TPM_RH_PLATFORM+{PP}
     *         Auth Index:1
     *         Auth Role: ADMIN
     *  @param keyHandle Handle of a public area that contains the TPM Vendor Authorization Key
     *         that will be used to validate manifestSignature
     *         Auth Index: None
     *  @param fuDigest Digest of the first block in the field upgrade sequence
     *  @param manifestSignature Signature over fuDigest using the key associated with keyHandle
     *         (not optional)
     *         One of: TPMS_SIGNATURE_RSASSA, TPMS_SIGNATURE_RSAPSS, TPMS_SIGNATURE_ECDSA,
     *         TPMS_SIGNATURE_ECDAA, TPMS_SIGNATURE_SM2, TPMS_SIGNATURE_ECSCHNORR, TPMT_HA,
     *         TPMS_SCHEME_HASH, TPMS_NULL_SIGNATURE.
     */
    public void FieldUpgradeStart(TPM_HANDLE authorization, TPM_HANDLE keyHandle, byte[] fuDigest, TPMU_SIGNATURE manifestSignature)
    {
        TPM2_FieldUpgradeStart_REQUEST req = new TPM2_FieldUpgradeStart_REQUEST(authorization, keyHandle, fuDigest, manifestSignature);
        DispatchCommand(TPM_CC.FieldUpgradeStart, req, null);
        return;
    }

    /** This command will take the actual field upgrade image to be installed on the TPM. The
     *  exact format of fuData is vendor-specific. This command is only possible following a
     *  successful TPM2_FieldUpgradeStart(). If the TPM has not received a properly authorized
     *  TPM2_FieldUpgradeStart(), then the TPM shall return TPM_RC_FIELDUPGRADE.

     *  @param fuData Field upgrade image data
     *  @return nextDigest - Tagged digest of the next block
     *                       TPM_ALG_NULL if field update is complete<br>
     *          firstDigest - Tagged digest of the first block of the sequence
     */
    public FieldUpgradeDataResponse FieldUpgradeData(byte[] fuData)
    {
        TPM2_FieldUpgradeData_REQUEST req = new TPM2_FieldUpgradeData_REQUEST(fuData);
        FieldUpgradeDataResponse resp = new FieldUpgradeDataResponse();
        DispatchCommand(TPM_CC.FieldUpgradeData, req, resp);
        return resp;
    }

    /** This command is used to read a copy of the current firmware installed in the TPM.

     *  @param sequenceNumber The number of previous calls to this command in this sequence
     *         set to 0 on the first call
     *  @return fuData - Field upgrade image data
     */
    public byte[] FirmwareRead(int sequenceNumber)
    {
        TPM2_FirmwareRead_REQUEST req = new TPM2_FirmwareRead_REQUEST(sequenceNumber);
        FirmwareReadResponse resp = new FirmwareReadResponse();
        DispatchCommand(TPM_CC.FirmwareRead, req, resp);
        return resp.fuData;
    }

    /** This command saves a session context, object context, or sequence object context
     *  outside the TPM.

     *  @param saveHandle Handle of the resource to save
     *         Auth Index: None
     *  @return context - This structure is used in TPM2_ContextLoad() and TPM2_ContextSave().
     *  If
     *                    the values of the TPMS_CONTEXT structure in TPM2_ContextLoad() are not
     *                    the same as the values when the context was saved (TPM2_ContextSave()),
     *                    then the TPM shall not load the context.
     */
    public TPMS_CONTEXT ContextSave(TPM_HANDLE saveHandle)
    {
        TPM2_ContextSave_REQUEST req = new TPM2_ContextSave_REQUEST(saveHandle);
        ContextSaveResponse resp = new ContextSaveResponse();
        DispatchCommand(TPM_CC.ContextSave, req, resp);
        return resp.context;
    }

    /** This command is used to reload a context that has been saved by TPM2_ContextSave().

     *  @param context The context blob
     *  @return handle - The handle assigned to the resource after it has been successfully loaded
     */
    public TPM_HANDLE ContextLoad(TPMS_CONTEXT context)
    {
        TPM2_ContextLoad_REQUEST req = new TPM2_ContextLoad_REQUEST(context);
        ContextLoadResponse resp = new ContextLoadResponse();
        DispatchCommand(TPM_CC.ContextLoad, req, resp);
        return resp.handle;
    }

    /** This command causes all context associated with a loaded object, sequence object, or
     *  session to be removed from TPM memory.

     *  @param flushHandle The handle of the item to flush
     *         NOTE This is a use of a handle as a parameter.
     */
    public void FlushContext(TPM_HANDLE flushHandle)
    {
        TPM2_FlushContext_REQUEST req = new TPM2_FlushContext_REQUEST(flushHandle);
        DispatchCommand(TPM_CC.FlushContext, req, null);
        return;
    }

    /** This command allows certain Transient Objects to be made persistent or a persistent
     *  object to be evicted.

     *  @param auth TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
     *         Auth Handle: 1
     *         Auth Role: USER
     *  @param objectHandle The handle of a loaded object
     *         Auth Index: None
     *  @param persistentHandle If objectHandle is a transient object handle, then this is the
     *         persistent handle for the object
     *         if objectHandle is a persistent object handle, then it shall be the same value as
     *         persistentHandle
     */
    public void EvictControl(TPM_HANDLE auth, TPM_HANDLE objectHandle, TPM_HANDLE persistentHandle)
    {
        TPM2_EvictControl_REQUEST req = new TPM2_EvictControl_REQUEST(auth, objectHandle, persistentHandle);
        DispatchCommand(TPM_CC.EvictControl, req, null);
        return;
    }

    /** This command reads the current TPMS_TIME_INFO structure that contains the current
     *  setting of Time, Clock, resetCount, and restartCount.

     *  @return currentTime - This structure is used in, e.g., the TPM2_GetTime() attestation and
     *                        TPM2_ReadClock().
     */
    public TPMS_TIME_INFO ReadClock()
    {
        TPM2_ReadClock_REQUEST req = new TPM2_ReadClock_REQUEST();
        ReadClockResponse resp = new ReadClockResponse();
        DispatchCommand(TPM_CC.ReadClock, req, resp);
        return resp.currentTime;
    }

    /** This command is used to advance the value of the TPMs Clock. The command will fail if
     *  newTime is less than the current value of Clock or if the new time is greater than
     *  FFFF00000000000016. If both of these checks succeed, Clock is set to newTime. If
     *  either of these checks fails, the TPM shall return TPM_RC_VALUE and make no change to Clock.

     *  @param auth TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
     *         Auth Handle: 1
     *         Auth Role: USER
     *  @param newTime New Clock setting in milliseconds
     */
    public void ClockSet(TPM_HANDLE auth, long newTime)
    {
        TPM2_ClockSet_REQUEST req = new TPM2_ClockSet_REQUEST(auth, newTime);
        DispatchCommand(TPM_CC.ClockSet, req, null);
        return;
    }

    /** This command adjusts the rate of advance of Clock and Time to provide a better
     *  approximation to real time.

     *  @param auth TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
     *         Auth Handle: 1
     *         Auth Role: USER
     *  @param rateAdjust Adjustment to current Clock update rate
     */
    public void ClockRateAdjust(TPM_HANDLE auth, TPM_CLOCK_ADJUST rateAdjust)
    {
        TPM2_ClockRateAdjust_REQUEST req = new TPM2_ClockRateAdjust_REQUEST(auth, rateAdjust);
        DispatchCommand(TPM_CC.ClockRateAdjust, req, null);
        return;
    }

    /** This command returns various information regarding the TPM and its current state.

     *  @param capability Group selection; determines the format of the response
     *  @param property Further definition of information
     *  @param propertyCount Number of properties of the indicated type to return
     *  @return moreData - Flag to indicate if there are more values of this type<br>
     *          capabilityData - The capability data
     */
    public GetCapabilityResponse GetCapability(TPM_CAP capability, int property, int propertyCount)
    {
        TPM2_GetCapability_REQUEST req = new TPM2_GetCapability_REQUEST(capability, property, propertyCount);
        GetCapabilityResponse resp = new GetCapabilityResponse();
        DispatchCommand(TPM_CC.GetCapability, req, resp);
        return resp;
    }

    /** This command is used to check to see if specific combinations of algorithm parameters
     *  are supported.

     *  @param parameters Algorithm parameters to be validated
     *         One of: TPMS_KEYEDHASH_PARMS, TPMS_SYMCIPHER_PARMS, TPMS_RSA_PARMS, TPMS_ECC_PARMS,
     *         TPMS_ASYM_PARMS.
     */
    public void TestParms(TPMU_PUBLIC_PARMS parameters)
    {
        TPM2_TestParms_REQUEST req = new TPM2_TestParms_REQUEST(parameters);
        DispatchCommand(TPM_CC.TestParms, req, null);
        return;
    }

    /** This command defines the attributes of an NV Index and causes the TPM to reserve space
     *  to hold the data associated with the NV Index. If a definition already exists at the
     *  NV Index, the TPM will return TPM_RC_NV_DEFINED.

     *  @param authHandle TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param auth The authorization value
     *  @param publicInfo The public parameters of the NV area
     */
    public void NV_DefineSpace(TPM_HANDLE authHandle, byte[] auth, TPMS_NV_PUBLIC publicInfo)
    {
        TPM2_NV_DefineSpace_REQUEST req = new TPM2_NV_DefineSpace_REQUEST(authHandle, auth, publicInfo);
        DispatchCommand(TPM_CC.NV_DefineSpace, req, null);
        return;
    }

    /** This command removes an Index from the TPM.

     *  @param authHandle TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param nvIndex The NV Index to remove from NV space
     *         Auth Index: None
     */
    public void NV_UndefineSpace(TPM_HANDLE authHandle, TPM_HANDLE nvIndex)
    {
        TPM2_NV_UndefineSpace_REQUEST req = new TPM2_NV_UndefineSpace_REQUEST(authHandle, nvIndex);
        DispatchCommand(TPM_CC.NV_UndefineSpace, req, null);
        return;
    }

    /** This command allows removal of a platform-created NV Index that has
     *  TPMA_NV_POLICY_DELETE SET.

     *  @param nvIndex Index to be deleted
     *         Auth Index: 1
     *         Auth Role: ADMIN
     *  @param platform TPM_RH_PLATFORM + {PP}
     *         Auth Index: 2
     *         Auth Role: USER
     */
    public void NV_UndefineSpaceSpecial(TPM_HANDLE nvIndex, TPM_HANDLE platform)
    {
        TPM2_NV_UndefineSpaceSpecial_REQUEST req = new TPM2_NV_UndefineSpaceSpecial_REQUEST(nvIndex, platform);
        DispatchCommand(TPM_CC.NV_UndefineSpaceSpecial, req, null);
        return;
    }

    /** This command is used to read the public area and Name of an NV Index. The public area
     *  of an Index is not privacy-sensitive and no authorization is required to read this data.

     *  @param nvIndex The NV Index
     *         Auth Index: None
     *  @return nvPublic - The public area of the NV Index<br>
     *          nvName - The Name of the nvIndex
     */
    public NV_ReadPublicResponse NV_ReadPublic(TPM_HANDLE nvIndex)
    {
        TPM2_NV_ReadPublic_REQUEST req = new TPM2_NV_ReadPublic_REQUEST(nvIndex);
        NV_ReadPublicResponse resp = new NV_ReadPublicResponse();
        DispatchCommand(TPM_CC.NV_ReadPublic, req, resp);
        return resp;
    }

    /** This command writes a value to an area in NV memory that was previously defined by
     *  TPM2_NV_DefineSpace().

     *  @param authHandle Handle indicating the source of the authorization value
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param nvIndex The NV Index of the area to write
     *         Auth Index: None
     *  @param data The data to write
     *  @param offset The octet offset into the NV Area
     */
    public void NV_Write(TPM_HANDLE authHandle, TPM_HANDLE nvIndex, byte[] data, int offset)
    {
        TPM2_NV_Write_REQUEST req = new TPM2_NV_Write_REQUEST(authHandle, nvIndex, data, offset);
        DispatchCommand(TPM_CC.NV_Write, req, null);
        return;
    }

    /** This command is used to increment the value in an NV Index that has the TPM_NT_COUNTER
     *  attribute. The data value of the NV Index is incremented by one.

     *  @param authHandle Handle indicating the source of the authorization value
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param nvIndex The NV Index to increment
     *         Auth Index: None
     */
    public void NV_Increment(TPM_HANDLE authHandle, TPM_HANDLE nvIndex)
    {
        TPM2_NV_Increment_REQUEST req = new TPM2_NV_Increment_REQUEST(authHandle, nvIndex);
        DispatchCommand(TPM_CC.NV_Increment, req, null);
        return;
    }

    /** This command extends a value to an area in NV memory that was previously defined by
     *  TPM2_NV_DefineSpace.

     *  @param authHandle Handle indicating the source of the authorization value
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param nvIndex The NV Index to extend
     *         Auth Index: None
     *  @param data The data to extend
     */
    public void NV_Extend(TPM_HANDLE authHandle, TPM_HANDLE nvIndex, byte[] data)
    {
        TPM2_NV_Extend_REQUEST req = new TPM2_NV_Extend_REQUEST(authHandle, nvIndex, data);
        DispatchCommand(TPM_CC.NV_Extend, req, null);
        return;
    }

    /** This command is used to SET bits in an NV Index that was created as a bit field. Any
     *  number of bits from 0 to 64 may be SET. The contents of bits are ORed with the current
     *  contents of the NV Index.

     *  @param authHandle Handle indicating the source of the authorization value
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param nvIndex NV Index of the area in which the bit is to be set
     *         Auth Index: None
     *  @param bits The data to OR with the current contents
     */
    public void NV_SetBits(TPM_HANDLE authHandle, TPM_HANDLE nvIndex, long bits)
    {
        TPM2_NV_SetBits_REQUEST req = new TPM2_NV_SetBits_REQUEST(authHandle, nvIndex, bits);
        DispatchCommand(TPM_CC.NV_SetBits, req, null);
        return;
    }

    /** If the TPMA_NV_WRITEDEFINE or TPMA_NV_WRITE_STCLEAR attributes of an NV location are
     *  SET, then this command may be used to inhibit further writes of the NV Index.

     *  @param authHandle Handle indicating the source of the authorization value
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param nvIndex The NV Index of the area to lock
     *         Auth Index: None
     */
    public void NV_WriteLock(TPM_HANDLE authHandle, TPM_HANDLE nvIndex)
    {
        TPM2_NV_WriteLock_REQUEST req = new TPM2_NV_WriteLock_REQUEST(authHandle, nvIndex);
        DispatchCommand(TPM_CC.NV_WriteLock, req, null);
        return;
    }

    /** The command will SET TPMA_NV_WRITELOCKED for all indexes that have their
     *  TPMA_NV_GLOBALLOCK attribute SET.

     *  @param authHandle TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
     *         Auth Index: 1
     *         Auth Role: USER
     */
    public void NV_GlobalWriteLock(TPM_HANDLE authHandle)
    {
        TPM2_NV_GlobalWriteLock_REQUEST req = new TPM2_NV_GlobalWriteLock_REQUEST(authHandle);
        DispatchCommand(TPM_CC.NV_GlobalWriteLock, req, null);
        return;
    }

    /** This command reads a value from an area in NV memory previously defined by TPM2_NV_DefineSpace().

     *  @param authHandle The handle indicating the source of the authorization value
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param nvIndex The NV Index to be read
     *         Auth Index: None
     *  @param size Number of octets to read
     *  @param offset Octet offset into the NV area
     *         This value shall be less than or equal to the size of the nvIndex data.
     *  @return data - The data read
     */
    public byte[] NV_Read(TPM_HANDLE authHandle, TPM_HANDLE nvIndex, int size, int offset)
    {
        TPM2_NV_Read_REQUEST req = new TPM2_NV_Read_REQUEST(authHandle, nvIndex, size, offset);
        NV_ReadResponse resp = new NV_ReadResponse();
        DispatchCommand(TPM_CC.NV_Read, req, resp);
        return resp.data;
    }

    /** If TPMA_NV_READ_STCLEAR is SET in an Index, then this command may be used to prevent
     *  further reads of the NV Index until the next TPM2_Startup (TPM_SU_CLEAR).

     *  @param authHandle The handle indicating the source of the authorization value
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param nvIndex The NV Index to be locked
     *         Auth Index: None
     */
    public void NV_ReadLock(TPM_HANDLE authHandle, TPM_HANDLE nvIndex)
    {
        TPM2_NV_ReadLock_REQUEST req = new TPM2_NV_ReadLock_REQUEST(authHandle, nvIndex);
        DispatchCommand(TPM_CC.NV_ReadLock, req, null);
        return;
    }

    /** This command allows the authorization secret for an NV Index to be changed.

     *  @param nvIndex Handle of the entity
     *         Auth Index: 1
     *         Auth Role: ADMIN
     *  @param newAuth New authorization value
     */
    public void NV_ChangeAuth(TPM_HANDLE nvIndex, byte[] newAuth)
    {
        TPM2_NV_ChangeAuth_REQUEST req = new TPM2_NV_ChangeAuth_REQUEST(nvIndex, newAuth);
        DispatchCommand(TPM_CC.NV_ChangeAuth, req, null);
        return;
    }

    /** The purpose of this command is to certify the contents of an NV Index or portion of an
     *  NV Index.

     *  @param signHandle Handle of the key used to sign the attestation structure
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param authHandle Handle indicating the source of the authorization value for the NV Index
     *         Auth Index: 2
     *         Auth Role: USER
     *  @param nvIndex Index for the area to be certified
     *         Auth Index: None
     *  @param qualifyingData User-provided qualifying data
     *  @param inScheme Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
     *         One of: TPMS_SIG_SCHEME_RSASSA, TPMS_SIG_SCHEME_RSAPSS, TPMS_SIG_SCHEME_ECDSA,
     *         TPMS_SIG_SCHEME_ECDAA, TPMS_SIG_SCHEME_SM2, TPMS_SIG_SCHEME_ECSCHNORR,
     *         TPMS_SCHEME_HMAC, TPMS_SCHEME_HASH, TPMS_NULL_SIG_SCHEME.
     *  @param size Number of octets to certify
     *  @param offset Octet offset into the NV area
     *         This value shall be less than or equal to the size of the nvIndex data.
     *  @return certifyInfo - The structure that was signed<br>
     *          signature - The asymmetric signature over certifyInfo using the key referenced
     *  by signHandle
     */
    public NV_CertifyResponse NV_Certify(TPM_HANDLE signHandle, TPM_HANDLE authHandle, TPM_HANDLE nvIndex, byte[] qualifyingData, TPMU_SIG_SCHEME inScheme, int size, int offset)
    {
        TPM2_NV_Certify_REQUEST req = new TPM2_NV_Certify_REQUEST(signHandle, authHandle, nvIndex, qualifyingData, inScheme, size, offset);
        NV_CertifyResponse resp = new NV_CertifyResponse();
        DispatchCommand(TPM_CC.NV_Certify, req, resp);
        return resp;
    }

    /** The purpose of this command is to obtain information about an Attached Component
     *  referenced by an AC handle.

     *  @param ac Handle indicating the Attached Component
     *         Auth Index: None
     *  @param capability Starting info type
     *  @param count Maximum number of values to return
     *  @return moreData - Flag to indicate whether there are more values<br>
     *          capabilitiesData - List of capabilities
     */
    public AC_GetCapabilityResponse AC_GetCapability(TPM_HANDLE ac, TPM_AT capability, int count)
    {
        TPM2_AC_GetCapability_REQUEST req = new TPM2_AC_GetCapability_REQUEST(ac, capability, count);
        AC_GetCapabilityResponse resp = new AC_GetCapabilityResponse();
        DispatchCommand(TPM_CC.AC_GetCapability, req, resp);
        return resp;
    }

    /** The purpose of this command is to send (copy) a loaded object from the TPM to an
     *  Attached Component.

     *  @param sendObject Handle of the object being sent to ac
     *         Auth Index: 1
     *         Auth Role: DUP
     *  @param authHandle The handle indicating the source of the authorization value
     *         Auth Index: 2
     *         Auth Role: USER
     *  @param ac Handle indicating the Attached Component to which the object will be sent
     *         Auth Index: None
     *  @param acDataIn Optional non sensitive information related to the object
     *  @return acDataOut - May include AC specific data or information about an error.
     */
    public TPMS_AC_OUTPUT AC_Send(TPM_HANDLE sendObject, TPM_HANDLE authHandle, TPM_HANDLE ac, byte[] acDataIn)
    {
        TPM2_AC_Send_REQUEST req = new TPM2_AC_Send_REQUEST(sendObject, authHandle, ac, acDataIn);
        AC_SendResponse resp = new AC_SendResponse();
        DispatchCommand(TPM_CC.AC_Send, req, resp);
        return resp.acDataOut;
    }

    /** This command allows qualification of the sending (copying) of an Object to an Attached
     *  Component (AC). Qualification includes selection of the receiving AC and the method of
     *  authentication for the AC, and, in certain circumstances, the Object to be sent may be
     *  specified.

     *  @param policySession Handle for the policy session being extended
     *         Auth Index: None
     *  @param objectName The Name of the Object to be sent
     *  @param authHandleName The Name associated with authHandle used in the TPM2_AC_Send() command
     *  @param acName The Name of the Attached Component to which the Object will be sent
     *  @param includeObject If SET, objectName will be included in the value in
     *  policySessionpolicyDigest
     */
    public void Policy_AC_SendSelect(TPM_HANDLE policySession, byte[] objectName, byte[] authHandleName, byte[] acName, byte includeObject)
    {
        TPM2_Policy_AC_SendSelect_REQUEST req = new TPM2_Policy_AC_SendSelect_REQUEST(policySession, objectName, authHandleName, acName, includeObject);
        DispatchCommand(TPM_CC.Policy_AC_SendSelect, req, null);
        return;
    }

    /** This command is used to set the time remaining before an Authenticated Countdown Timer
     *  (ACT) expires.

     *  @param actHandle Handle of the selected ACT
     *         Auth Index: 1
     *         Auth Role: USER
     *  @param startTimeout The start timeout value for the ACT in seconds
     */
    public void ACT_SetTimeout(TPM_HANDLE actHandle, int startTimeout)
    {
        TPM2_ACT_SetTimeout_REQUEST req = new TPM2_ACT_SetTimeout_REQUEST(actHandle, startTimeout);
        DispatchCommand(TPM_CC.ACT_SetTimeout, req, null);
        return;
    }

    /** This is a placeholder to allow testing of the dispatch code.

     *  @param inputData Dummy data
     *  @return outputData - Dummy data
     */
    public byte[] Vendor_TCG_Test(byte[] inputData)
    {
        TPM2_Vendor_TCG_Test_REQUEST req = new TPM2_Vendor_TCG_Test_REQUEST(inputData);
        Vendor_TCG_TestResponse resp = new Vendor_TCG_TestResponse();
        DispatchCommand(TPM_CC.Vendor_TCG_Test, req, resp);
        return resp.outputData;
    }

}

//<<<
