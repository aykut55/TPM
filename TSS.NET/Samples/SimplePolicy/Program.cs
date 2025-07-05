﻿/*
 * Copyright (c) 2013  Microsoft Corporation
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Tpm2Lib;

namespace Policy
{
    /// <summary>
    /// Main class to contain this sample program.
    /// </summary>
    class Program
    {
        /// <summary>
        /// Defines the argument to use to have this program use a TCP connection
        /// to communicate with a TPM 2.0 simulator.
        /// </summary>
        private const string DeviceSimulator = "-tcp";

        /// <summary>
        /// Defines the argument to use to have this program use the Windows TBS
        /// API to communicate with a TPM 2.0 device.
        /// </summary>
        private const string DeviceWinTbs = "-tbs";

        /// <summary>
        /// The default connection to use for communication with the TPM.
        /// </summary>
        private const string DefaultDevice = DeviceSimulator;

        /// <summary>
        /// If using a TCP connection, the default DNS name/IP address for the
        /// simulator.
        /// </summary>
        private const string DefaultSimulatorName = "127.0.0.1";

        /// <summary>
        /// If using a TCP connection, the default TCP port of the simulator.
        /// </summary>
        private const int DefaultSimulatorPort = 2321;

        /// <summary>
        /// Prints instructions for usage of this program.
        /// </summary>
        static void WriteUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Usage: Policy [<device>]");
            Console.WriteLine();
            Console.WriteLine("    <device> can be '{0}' or '{1}'. Defaults to '{2}'.", DeviceWinTbs, DeviceSimulator, DefaultDevice);
            Console.WriteLine("        If <device> is '{0}', the program will connect to a simulator\n" +
                              "        listening on a TCP port.", DeviceSimulator);
            Console.WriteLine("        If <device> is '{0}', the program will use the TBS interface to talk\n" +
                              "        to the TPM device.", DeviceWinTbs);
        }

        /// <summary>
        /// Parse the arguments of the program and return the selected values.
        /// </summary>
        /// <param name="args">The arguments of the program.</param>
        /// <param name="tpmDeviceName">The name of the selected TPM connection created.</param>
        /// <returns>True if the arguments could be parsed. False if an unknown argument or 
        /// malformed argument was present.</returns>
        static bool ParseArguments(IEnumerable<string> args, out string tpmDeviceName)
        {
            tpmDeviceName = DefaultDevice;
            foreach (string arg in args)
            {
                if (string.Compare(arg, DeviceSimulator, true) == 0)
                {
                    tpmDeviceName = DeviceSimulator;
                }
                else if (string.Compare(arg, DeviceWinTbs, true) == 0)
                {
                    tpmDeviceName = DeviceWinTbs;
                }
                else
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Create a sealed-object primary that can be accessed with the given policy. SHA256 is assumed.
        /// </summary>
        /// <param name="tpm"></param>
        /// <param name="dataToSeal"></param>
        /// <param name="authValue"></param>
        /// <param name="policy"></param>
        /// <returns></returns>
        private static TpmHandle CreateSealedPrimaryObject(Tpm2 tpm, byte[] dataToSeal, byte[] authValue, byte[] policy)
        {
            ObjectAttr attrs = ObjectAttr.FixedTPM | ObjectAttr.FixedParent;

            if (authValue != null)
            {
                attrs |= ObjectAttr.UserWithAuth;
            }

            byte[] policyVal = policy ?? null;
            var sealedInPublic = new TpmPublic(TpmAlgId.Sha256,
                                               attrs,
                                               policyVal,
                                               new KeyedhashParms(new NullSchemeKeyedhash()),
                                               new Tpm2bDigestKeyedhash());

            //
            // Envelope for sealed data and auth
            // 
            byte[] authVal = authValue ?? null;
            var sealedInSensitive = new SensitiveCreate(authVal, dataToSeal);

            TkCreation creationTicket;
            byte[] creationHashSealed;
            TpmPublic sealedPublic;
            CreationData sealedCreationData;

            //
            // AuthValue encapsulates an authorization value: essentially a byte-array.
            // OwnerAuth is the owner authorization value of the TPM-under-test.  We
            // assume that it (and other) auths are set to the default (null) value.
            // If running on a real TPM, which has been provisioned by Windows, this
            // value will be different. An administrator can retrieve the owner
            // authorization value from the registry.
            //
            var ownerAuth = new AuthValue();

            //
            // Ask the TPM to create a primary containing the "sealed" data
            // 
            TpmHandle primHandle = tpm[ownerAuth].CreatePrimary(TpmHandle.RhOwner,
                                                                sealedInSensitive,
                                                                sealedInPublic,
                                                                null,
                                                                new PcrSelection[0],
                                                                out sealedPublic,
                                                                out sealedCreationData,
                                                                out creationHashSealed,
                                                                out creationTicket);
            return primHandle;
        }

        /// <summary>
        /// This sample illustrates the use of a simple TPM policy session. The policy demands
        /// PCR 1, 2, 3 set to current values, and the command be issued at locality zero.
        /// </summary>
        static void SimplePolicy(Tpm2 tpm)
        {
            Console.WriteLine("Simple Policy sample:");

            //
            // Check if policy commands are implemented by TPM. This list
            // could include all the other used commands as well.
            // This check here makes sense for policy commands, because
            // usually a policy has to be executed in full. If a command
            // out of the chain of policy commands is not implemented in the
            // TPM, the policy cannot be satisfied.
            // 
            var usedCommands = new[] { TpmCc.PolicyPCR };
            foreach (var commandCode in usedCommands)
            {
                if (!tpm.Helpers.IsImplemented(commandCode))
                {
                    Console.WriteLine("Cancel Simple Policy sample, because command {0} is not implemented by TPM.", commandCode);
                    return;
                }
            }

            //
            // First read the PCR values
            // 
            var pcrs = new uint[] { 1, 2, 3 };
            var sel = new PcrSelection(TpmAlgId.Sha, pcrs);

            PcrSelection[] selOut;
            Tpm2bDigest[] pcrValues;

            tpm.PcrRead(new[] { sel }, out selOut, out pcrValues);

            Console.WriteLine("PCR Selections:\n");
            foreach (PcrSelection s in selOut)
            {
                Console.WriteLine(s.ToString());
            }

            Console.WriteLine("PCR Values:\n");
            foreach (var v in pcrValues)
            {
                Console.WriteLine(v.ToString());
            }

            //
            // Save the current PCR values in a convenient data structure
            // 
            var expectedPcrVals = new PcrValueCollection(selOut, pcrValues);

            //
            // TSS.Net encapsulates a set of policy assertions as the PolicyTree class.  
            // 
            var policy = new PolicyTree(TpmAlgId.Sha256);

            //
            // Set the policy: Locality AND PolicyPcr. This form of CreatePOlicy
            // only creates a single chain. Note that all well-formed policy chains
            // must have leaf identifiers. Leaf identifiers are just strings that
            // are unique in a policy so that the framework can be told what
            // chain to evaluate.
            // 
            policy.Create(
                new PolicyAce[] 
                {
                    new TpmPolicyPcr(expectedPcrVals),
                    "leaf"
                }
            );

            //
            // Ask TSS.Net for the expected policy-hash for this policy
            // 
            TpmHash expectedPolicyHash = policy.GetPolicyDigest();

            //
            // Create a sealed primary object with the policy-hash we just calculated
            // 
            var dataToSeal = new byte[] { 1, 2, 3, 4, 5, 4, 3, 2, 1 };
            TpmHandle primHandle = CreateSealedPrimaryObject(tpm,
                                                             dataToSeal,
                                                             null,
                                                             expectedPolicyHash);
            //
            // Create an actual TPM policy session to evaluate the policy
            //
            AuthSession session = tpm.StartAuthSessionEx(TpmSe.Policy, TpmAlgId.Sha256);

            //
            // Run the policy on the TPM
            // 
            session.RunPolicy(tpm, policy, "leaf");

            //
            // Unseal the object
            //
            byte[] unsealedData = tpm[session].Unseal(primHandle);
            Console.WriteLine("Unsealed data: " + BitConverter.ToString(unsealedData));

            //
            // Change a PCR and make sure that the policy no longer works
            // 
            var nullAuth = new AuthValue();
            tpm[nullAuth].PcrEvent(TpmHandle.Pcr(3), new byte[] { 1, 2, 3 });
            tpm.PolicyRestart(session.Handle);

            //
            // Run the policy again - an error will be returned
            // 
            TpmRc policyError = session.RunPolicy(tpm, policy, null, true);

            //
            // And the session will be unusable
            // 
            unsealedData = tpm[session]._ExpectError(TpmRc.PolicyFail).Unseal(primHandle);

            //
            // Clean up
            // 
            tpm.FlushContext(session.Handle);
            tpm.FlushContext(primHandle);
        }

        /// <summary>
        /// This sample illustrates the use of a TpmPolicyOr.
        /// </summary>
        static void PolicyOr(Tpm2 tpm)
        {
            Console.WriteLine("PolicyOr sample:");

            //
            // Check if policy commands are implemented by TPM. This list
            // could include all the other used commands as well.
            // This check here makes sense for policy commands, because
            // usually a policy has to be executed in full. If a command
            // out of the chain of policy commands is not implemented in the
            // TPM, the policy cannot be satisfied.
            // 
            var usedCommands = new[] {
                                        TpmCc.PolicyPCR,
                                        TpmCc.PolicyAuthValue
            };
            foreach (var commandCode in usedCommands)
            {
                if (!tpm.Helpers.IsImplemented(commandCode))
                {
                    Console.WriteLine("Cancel Policy OR sample, because command {0} is not implemented by TPM.", commandCode);
                    return;
                }
            }

            var pcrs = new uint[] { 1, 2, 3 };
            var sel = new PcrSelection(TpmAlgId.Sha, pcrs);

            PcrSelection[] selOut;
            Tpm2bDigest[] pcrValues;

            //
            // First read the PCR values
            // 
            tpm.PcrRead(new[] { sel }, out selOut, out pcrValues);

            //
            // Save the current PCR values in a convenient data structure
            // 
            var expectedPcrVals = new PcrValueCollection(selOut, pcrValues);

            //
            // TSS.Net encapsulates a set of policy assertions as the PolicyTree class.  
            // 
            var policy = new PolicyTree(TpmAlgId.Sha256);

            //
            // First branch of PolicyOr
            // 
            var branch1 = new PolicyAce[]
            {
                new TpmPolicyPcr(expectedPcrVals), 
                "branch_1"
            };

            //
            // Second branch of PolicyOr
            //
            var branch2 = new PolicyAce[]
            {
                new TpmPolicyAuthValue(),
                "branch_2"
            };

            //
            // Create the policy. CreateNormalizedPolicy takes an array-of-arrays
            // of PolicyACEs that are to be OR'ed together (the branches themselves cannot
            // contain TpmPOlicyOrs). The library code constructs a policy tree with 
            // minimum number of TpmPolicyOrs at the root.  
            // 
            policy.CreateNormalizedPolicy(new[] { branch1, branch2 });

            //
            // Ask TSS.Net for the expected policy-hash for this policy
            // 
            TpmHash expectedPolicyHash = policy.GetPolicyDigest();

            //
            // Create a sealed primary object with the policy-hash we just calculated
            // 
            var dataToSeal = new byte[] { 1, 2, 3, 4, 5, 4, 3, 2, 1 };
            var authVal = new byte[] { 1, 2 };
            TpmHandle primHandle = CreateSealedPrimaryObject(tpm,
                                                             dataToSeal,
                                                             authVal,
                                                             expectedPolicyHash.HashData);
            //
            // Create an actual TPM policy session to evaluate the policy
            // 
            AuthSession session = tpm.StartAuthSessionEx(TpmSe.Policy, TpmAlgId.Sha256);

            //
            // Run the policy on the TPM
            // 
            session.RunPolicy(tpm, policy, "branch_1");

            //
            // And unseal the object
            // 
            byte[] unsealedData = tpm[session].Unseal(primHandle);
            Console.WriteLine("Unsealed data for branch_1: " + BitConverter.ToString(unsealedData));

            //
            // Now run the other branch
            // 
            tpm.PolicyRestart(session.Handle);
            session.RunPolicy(tpm, policy, "branch_2");

            //
            // And the session will be unusable
            // 
            unsealedData = tpm[session].Unseal(primHandle);
            Console.WriteLine("Unsealed data for branch_2: " + BitConverter.ToString(unsealedData));

            //
            // Clean up
            // 
            tpm.FlushContext(session.Handle);
            tpm.FlushContext(primHandle);
        }

        /// <summary>
        /// This sample demonstrates how policies can be created in a standard
        /// form and then shared between hosts.
        /// </summary>
        static void PolicySerialization()
        {
            Console.WriteLine("Policy serialization and de-serialization sample:");

            //
            // Create a policy session with two branches
            //
            var policy0 = new PolicyTree(TpmAlgId.Sha256);

            policy0.CreateNormalizedPolicy(new[] {
                new PolicyAce[]
                {
                    new TpmPolicyPassword(), 
                    //
                    // We can use an unsupported command when only serializing
                    // and deserializing. Execution of the policy might fail.
                    //
                    new TpmPolicyLocality(LocalityAttr.LocZero),
                    new TpmPolicyChainId("branch_1")
                },
                new PolicyAce[]
                {
                    new TpmPolicyPassword(), 
                    new TpmPolicyCommand(TpmCc.ChangeEPS),
                    "branch_2"
                }
            });

            //
            // And save it to disk as XML
            //
            const string fileName = "PolicySerialization.xml";
            policy0.SerializeToFile("Test Policy", PolicySerializationFormat.Xml, fileName);

            //
            // Now recover it into a new session 
            //
            var policy1 = new PolicyTree(TpmAlgId.Sha256);
            policy1.DeserializeFromFile(PolicySerializationFormat.Xml, fileName);

            //
            // And check that the two policies are the same
            //
            if (policy0.GetPolicyDigest() != policy1.GetPolicyDigest())
            {
                throw new Exception("Policy library error");
            }

            Console.WriteLine("Serialized policy to {0}.", fileName);

            //
            // And now do the same, but serialized to JSON
            //
            const string fileNameJ = "PolicySerialization.json";
            policy0.SerializeToFile("Test Policy", PolicySerializationFormat.Json, fileNameJ);

            //
            // Now recover it into a new session 
            //
            var policy1J = new PolicyTree(TpmAlgId.Sha256);
            policy1J.DeserializeFromFile(PolicySerializationFormat.Json, fileNameJ);

            //
            // And check that the two policies are the same
            //
            if (policy0.GetPolicyDigest() != policy1J.GetPolicyDigest())
            {
                throw new Exception("Policy library error");
            }

            Console.WriteLine("Serialized policy to {0}.", fileNameJ);
        }

        /// <summary>
        /// We have to share the signing key to sign a policy between the 
        /// creator of the policy (PolicyEvaluationWithCallback) and the
        /// user of the policy - the one running the policy. In this sample,
        /// we use a global variable to do that. In real life, the creator
        /// of the policy has to provide the user with the signing key.
        /// </summary>
        static private AsymCryptoSystem _publicSigningKey;

        /// <summary>
        /// Use this internal member for this sample only. We have different
        /// expiration times and to be able to use one signature callback
        /// for all of them, use this variable to communicate the expected
        /// expiration time.
        /// </summary>
        static private int _expectedExpirationTime;

        /// <summary>
        /// The callback to sign the TpmPolicySignature challenge from the TPM.
        /// </summary>
        /// <param name="policyTree">The policy tree to check.</param>
        /// <param name="ace">The policy element (TpmPolicySignature) to evaluate.</param>
        /// <param name="nonceTpm">The nonce from the TPM.</param>
        /// <returns>Signature of the nonce.</returns>
        public static ISignatureUnion SignerCallback(PolicyTree policyTree, TpmPolicySigned ace,
                                                     byte[] nonceTpm, out TpmPublic verificationKey)
        {
            //
            // This function checks the parameters of the associated TpmPolicySigned
            // ACE, and if they are those expected the TPM challenge is signed.
            // Note that policy expressions are often obtained from untrustworthy
            // sources, so it is important for key-holders to check what they 
            // are bing asked to do before signing anything.
            //

            // 
            // The policy just contains the name of the signature verification key, however the
            // TPM needs the actual public key to verify the signature.  Check that the name
            // matches, and if it does return the public key.
            //
            byte[] expectedName = _publicSigningKey.GetPublicParms().GetName();
            if (!expectedName.SequenceEqual(ace.AuthObjectName))
            {
                throw new Exception("Unexpected name in policy.");
            }
            verificationKey = _publicSigningKey.GetPublicParms();

            // 
            // Check that the key is the one that we expect
            // 
            if (ace.NodeId != "Signing Key 1")
            {
                throw new Exception("Unrecognized key");
            }


            //
            // Check that nonceTom is not null (otherwise anything we sign can
            // be used for any session).
            // 
            if (Globs.IsEmpty(nonceTpm))
            {
                throw new Exception("Sign challenges with expiration time need nonce.");
            }
            
            //
            // Check PolicyRef and cpHash are what we want to sign
            // 
            if (!Globs.IsEmpty(ace.CpHash))
            {
                throw new Exception("I only sign null-cpHash");
            }

            if (!ace.PolicyRef.SequenceEqual(new byte[] { 1, 2, 3, 4 }))
            {
                throw new Exception("Incorrect PolicyRef");
            }

            //
            // And finally check that the expiration is set correctly. Check for
            // positive values (simple signing policy) and negative values (sining 
            // policy with ticket).
            // 
            if (ace.ExpirationTime != _expectedExpirationTime)
            {
                throw new Exception("Unexpected expiration time");
            }

            //
            // Everything is OK, so get a formatted bloc containing the challenge 
            // data and then sign it.
            // 
            byte[] dataToSign = PolicyTree.PackDataToSign(ace.ExpirationTime, nonceTpm,
                                                          ace.CpHash, ace.PolicyRef);
            return  _publicSigningKey.Sign(dataToSign);
        }

        /// <summary>
        /// Some policies can be evaluated solely from public parts of the policy.
        /// Others need a private keyholder to sign some data. TSS.Net provides a
        /// callback facility for these cases. In this sample the callback 
        /// signs some data using a software key. But the callback might also 
        /// ask for a smartcard to sign a challenge, etc.
        /// </summary>
        /// <param name="tpm">reference to the TPM2 object to use.</param>
        static void PolicyEvaluationWithCallback(Tpm2 tpm)
        {
            Console.WriteLine("Policy evaluation with callback sample.");

            //
            // Check if policy commands are implemented by TPM. This list
            // could include all the other used commands as well.
            // This check here makes sense for policy commands, because
            // usually a policy has to be executed in full. If a command
            // out of the chain of policy commands is not implemented in the
            // TPM, the policy cannot be satisfied.
            // 
            var usedCommands = new[] {
                                        TpmCc.PolicySigned,
                                        TpmCc.PolicyGetDigest
            };
            foreach (var commandCode in usedCommands)
            {
                if (!tpm.Helpers.IsImplemented(commandCode))
                {
                    Console.WriteLine("Cancel Policy evaluation callback sample, because command {0} is not implemented by TPM.", commandCode);
                    return;
                }
            }

            //
            // Template for a software signing key
            // 
            var signKeyPublicTemplate = new TpmPublic(TpmAlgId.Sha256,
                                                      ObjectAttr.Sign | ObjectAttr.Restricted,
                                                      null,
                                                      new RsaParms(SymDefObject.NullObject(),
                                                                   new SchemeRsassa(TpmAlgId.Sha1),
                                                                   2048, 0),
                                                      new Tpm2bPublicKeyRsa());
            //
            // Create a new random key
            // 
            _publicSigningKey = new AsymCryptoSystem(signKeyPublicTemplate);

            //
            // Create a policy containing a TpmPolicySigned referring to the new 
            // software signing key.
            // 
            _expectedExpirationTime = 60;
            var policy = new PolicyTree(TpmAlgId.Sha256);

            policy.Create(
                new PolicyAce[]
                {
                    new TpmPolicySigned(_publicSigningKey.GetPublicParms().GetName(), 
                                                                            // Newly created PubKey
                                        true,                               // nonceTpm required, expiration time is given
                                        _expectedExpirationTime,            // expirationTime for policy
                                        null,                        // cpHash
                                        new byte[] {1, 2, 3, 4})            // policyRef
                                        {NodeId = "Signing Key 1"},         // Distinguishing name
                                        new TpmPolicyChainId("leaf")        // Signed data
                });

            //
            // Compute the expected hash for the policy session. This hash would be
            // used in the object associated with the policy to confirm that the 
            // policy is actually fulfilled.
            // 
            TpmHash expectedHash = policy.GetPolicyDigest();

            //
            // The use of the object associated with the policy has to evaluate the
            // policy. In order to process TpmPolicySigned the caller will have to 
            // sign a data structure challenge from the TPM. Here we install a 
            // callback that will sign the challenge from the TPM. 
            // 
            policy.SetSignerCallback(SignerCallback);

            //
            // Evaluate the policy. TSS.Net will traverse the policy tree from leaf to 
            // root (in this case just TpmPolicySigned) and will call the signer callback
            // to get a properly-formed challenge signed.
            // 
            AuthSession authSession = tpm.StartAuthSessionEx(TpmSe.Policy, TpmAlgId.Sha256);
            authSession.RunPolicy(tpm, policy, "leaf");

            //
            // And check that the TPM policy hash is what we expect
            // 
            byte[] actualHash = tpm.PolicyGetDigest(authSession.Handle);

            if (expectedHash != actualHash)
            {
                throw new Exception("Policy evaluation error");
            }

            Console.WriteLine("TpmPolicySignature evaluated.");

            //
            // Clean up
            // 
            tpm.FlushContext(authSession.Handle);
        }

        /// <summary>
        /// The signer of the policy element (the callback) has to know the object handle.
        /// </summary>
        static private TpmHandle _hSealedObj;

        /// <summary>
        /// Some policies can be evaluated solely from public parts of the policy.
        /// Others needs a private keyholder to sign some data. TSS.Net provides 
        /// a callback facility for these cases.  
        /// 
        /// This second sample illustrates the use of callbacks to provide authData.
        /// </summary>
        /// <param name="tpm">Reference to the TPM object to use.</param>
        static void PolicyEvaluationWithCallback2(Tpm2 tpm)
        {
            Console.WriteLine("Policy evaluation with callback sample 2.");

            //
            // Check if policy commands are implemented by TPM. This list
            // could include all the other used commands as well.
            // This check here makes sense for policy commands, because
            // usually a policy has to be executed in full. If a command
            // out of the chain of policy commands is not implemented in the
            // TPM, the policy cannot be satisfied.
            // 
            var usedCommands = new[] {
                                        TpmCc.PolicySecret,
                                        TpmCc.PolicyGetDigest,
                                        TpmCc.PolicyRestart
            };
            foreach (var commandCode in usedCommands)
            {
                if (!tpm.Helpers.IsImplemented(commandCode))
                {
                    Console.WriteLine("Cancel Policy evaluation callback 2 sample, because command {0} is not implemented by TPM.", commandCode);
                    return;
                }
            }

            //
            // Create an object with a random AuthValue. The type of object is immaterial
            // (it can even be the owner). In order to construct the policy we will 
            // need the name and to prove that we know the AuthVal.
            // 
            var dataToSeal = new byte[] { 1, 2, 3, 4 };
            _hSealedObj = CreateSealedPrimaryObject(tpm, dataToSeal,
                                                    AuthValue.FromRandom(10), null);
            var policy = new PolicyTree(TpmAlgId.Sha256);

            policy.Create(
                new PolicyAce[]
                    {
                            new TpmPolicySecret(_hSealedObj,     // Object providing auth value to the TPM
                                                true,       // Include nonceTpm
                                                0,          // Never expires (until reboot)
                                                null,       // Not bound to a cpHash
                                                null),      // Null policyRef
                            "leaf"                              // Name for this ACE
                    });

            TpmHash expectedHash = policy.GetPolicyDigest();

            //
            // We are about to ask for the session to be evaluated, but in order
            // to process TpmPolicySecret the caller will have to prove knowledge of 
            // the authValue associated with objectName. In this first version we
            // do this with PWAP.
            // 
            AuthSession authSession = tpm.StartAuthSessionEx(TpmSe.Policy, TpmAlgId.Sha256);
            authSession.RunPolicy(tpm, policy, "leaf");

            //
            // The policy evaluated.  But is the digest what we expect?
            // 
            byte[] digestIs = tpm.PolicyGetDigest(authSession.Handle);
            if (expectedHash != digestIs)
            {
                throw new Exception("Incorrect PolicyDigest");
            }

            //
            // The policy evaluated. But is the digest what we expect?
            // 
            digestIs = tpm.PolicyGetDigest(authSession.Handle);
            if (expectedHash != digestIs)
            {
                throw new Exception("Incorrect PolicyDigest");
            }
            Console.WriteLine("TpmPolicySignature evaluated.");

            tpm.FlushContext(authSession.Handle);
        }

        /// <summary>
        /// This sample demonstrates the creation of a signing "primary" key and use of this
        /// key to sign data, and use of the TPM and TSS.Net to validate the signature.
        /// </summary>
        /// <param name="args">Arguments to this program.</param>
        static void Main(string[] args)
        {
            string tpmDeviceName;

            //
            // Parse the program arguments. If the wrong arguments are given or
            // are malformed, then instructions for usage are displayed and 
            // the program terminates.
            // 
            if (!ParseArguments(args, out tpmDeviceName))
            {
                WriteUsage();
                return;
            }

            try
            {
                //
                // Create the device according to the selected connection.
                // 
                Tpm2Device tpmDevice;
                switch (tpmDeviceName)
                {
                    case DeviceSimulator:
                        tpmDevice = new TcpTpmDevice(DefaultSimulatorName, DefaultSimulatorPort);
                        break;

                    case DeviceWinTbs:
                        tpmDevice = new TbsDevice();
                        break;

                    default:
                        throw new Exception("Unknown device selected.");
                }

                //
                // Connect to the TPM device. This function actually establishes the connection.
                // 
                tpmDevice.Connect();

                //
                // Pass the device object used for communication to the TPM 2.0 object
                // which provides the command interface.
                // 
                var tpm = new Tpm2(tpmDevice);
                if (tpmDevice is TcpTpmDevice)
                {
                    //
                    // If we are using the simulator, we have to do a few things the
                    // firmware would usually do. These actions have to occur after
                    // the connection has been established.
                    // 
                    tpmDevice.PowerCycle();
                    tpm.Startup(Su.Clear);
                }

                //
                // Run individual tests.
                // 
                SimplePolicy(tpm);
                PolicyOr(tpm);
                PolicySerialization();
                PolicyEvaluationWithCallback(tpm);
                PolicyEvaluationWithCallback2(tpm);

                //
                // Clean up.
                // 
                tpm.Dispose();
            }
            catch (TpmException e)
            {
                //
                // If a command fails because an unexpected return code is in the response,
                // i.e., TPM returns an error code where success is expected or success
                // where an error code is expected. Or if the response is malformed, then
                // the unmarshaling code will throw a TPM exception.
                // The Error string will contain a description of the return code. Usually the
                // return code will be a known TPM return code. However, if using the TPM through
                // TBS, TBS might encode internal error codes into the response code. For instance
                // a return code of 0x80280400 indicates that a command is blocked by TBS. This
                // error code is also returned if the command is not implemented by the TPM.
                // 
                // You can see the information included in the TPM exception by removing the
                // checks for available TPM commands above and running the sample on a TPM
                // without the required commands.
                // 
                Console.WriteLine("TPM exception occurred: {0}", e.ErrorString);
                Console.WriteLine("Call stack: {0}", e.StackTrace);
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception occurred: {0}", e.Message);
            }

            Console.WriteLine("Press Any Key to continue.");

            Console.ReadLine();
        }
    }
}
