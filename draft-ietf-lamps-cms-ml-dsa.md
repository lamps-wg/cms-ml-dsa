---
title: "Use of the ML-DSA Signature Algorithm in the Cryptographic Message Syntax (CMS)"
abbrev: "ML-DSA in CMS"
category: std

docname: draft-ietf-lamps-cms-ml-dsa-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "LAMPS"
keyword:
  - cms
  - ml-dsa
  - dilithium
venue:
  # group: "Limited Additional Mechanisms for PKIX and SMIME"
  # type: "Working Group"
  # mail: "spasm@ietf.org"
  # arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  # github: "lamps-wg/cms-ml-dsa"
  # latest: "https://lamps-wg.github.io/cms-ml-dsa/draft-ietf-lamps-cms-ml-dsa.html"

author:
  -
    fullname: Ben Salter
    organization: UK National Cyber Security Centre
    email: ben.s3@ncsc.gov.uk
  -
    fullname: Adam Raine
    organization: UK National Cyber Security Centre
    email: adam.r@ncsc.gov.uk
  -
    fullname: Daniel Van Geest
    ins: D. Van Geest
    organization: CryptoNext Security
    email: daniel.vangeest@cryptonext-security.com

normative:
  FIPS204:
    target: https://csrc.nist.gov/pubs/fips/204/final
    title: Module-Lattice-Based Digital Signature Standard
    author:
      name: National Institute of Standards and Technology
      ins: NIST
    date: 2024-08-13
  CSOR:
    target: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
    title: Computer Security Objects Register
    author:
      name: National Institute of Standards and Technology
      ins: NIST
    date: 2024-08-20
  RFC5652:

informative:
  FIPS202: DOI.10.6028/NIST.FIPS.202
  FIPS203: DOI.10.6028/NIST.FIPS.203
  RFC5911:
  X680:
    target: https://www.itu.int/rec/T-REC-X.680
    title: "Information Technology - Abstract Syntax Notation One (ASN.1): Specification of basic notation. ITU-T Recommendation X.680 (2021) | ISO/IEC 8824-1:2021."
    author:
      org: ITU-T
    date: February 2021
---

--- abstract

The Module-Lattice-Based Digital Signature Algorithm (ML-DSA), as defined in FIPS 204, is a post-quantum digital signature scheme that aims to be secure against an adversary in posession of a Cryptographically Relevant Quantum Computer (CRQC).
This document specifies the conventions for using the ML-DSA signature algorithm with the Cryptographic Message Syntax (CMS).
In addition, the algorithm identifier and public key syntax are provided.


--- middle

# Introduction

The Module-Lattice-Based Digital Signature Algorithm (ML-DSA) is a digital signature algorithm standardised by NIST as part of their post-quantum cryptography standardization process.
It is intended to be secure against both "traditional" cryptographic attacks, as well as attacks utilising a quantum computer.
It offers smaller signatures and significantly faster runtimes than SLH-DSA {{FIPS203}}, an alternative post-quantum signature algorithm also standardised by NIST.

Prior to standardisation, the algorithm was known as Dilithium.  ML-DSA and Dilithium are not compatible.

ML-DSA offers parameter sets that meet three security levels: ML-DSA-44, ML-DSA-65, and ML-DSA-87.
ML-DSA-44 is intended to meet NIST's level 2 security category, ML-DSA-65 is intended to meet level 3, and ML-DSA-87 is intended to meet level 5.
Each category requires that algorithms be as resistant to attack as a particular cryptographic algorithm.
Attacks on algorithms in the level 2 category are intended to be at least as hard as performing a collision search on SHA256.
Attacks on algorithms in the level 3 category are intended to be at least as hard as performing an exhaustive key search on AES192.
Attacks on algorithms in the level 5 category are intended to be at least as hard as performing an exhaustive key search on AES256.

EDNOTE: Appendix B of draft-ietf-lamps-dilithium-certificates describes this well, if it's easier just to refer to that.

For each of the ML-DSA parameter sets, an algorithm identifier OID has been specified.

{{FIPS204}} also specifies a pre-hashed variant of ML-DSA, called HashML-DSA.
HashML-DSA is not used in CMS.


## Conventions and Definitions

{::boilerplate bcp14-tagged}


# ML-DSA Algorithm Identifiers {#ml-dsa-algorithm-identifiers}

Many ASN.1 data structure types use the AlgorithmIdentifier type to identify cryptographic algorithms.
In CMS, AlgorithmIdentifiers are used to identify ML-DSA signatures in the signed-data content type.
They may also appear in X.509 certificates used to verify those signatures.
{{?I-D.ietf-lamps-dilithium-certificates}} describes the use of ML-DSA in X.509 certificates.
The AlgorithmIdentifier type, which is included herein for convenience, is defined as follows:

~~~ asn.1
AlgorithmIdentifier{ALGORITHM-TYPE, ALGORITHM-TYPE:AlgorithmSet} ::=
        SEQUENCE {
            algorithm   ALGORITHM-TYPE.&id({AlgorithmSet}),
            parameters  ALGORITHM-TYPE.
                   &Params({AlgorithmSet}{@algorithm}) OPTIONAL
        }
~~~

The above syntax is from {{?RFC5911}} and is compatible with the 2021 ASN.1 syntax {{X680}}.
See {{?RFC5280}} for the 1988 ASN.1 syntax.

The fields in the AlgorithmIdentifier type have the following meanings:

algorithm:

: The algorithm field contains an OID that identifies the cryptographic algorithm in use.
The OIDs for ML-DSA are described below.

parameters:

: The parameters field contains parameter information for the algorithm identified by the OID in the algorithm field.
Each ML-DSA parameter set is identified by its own algorithm OID, so there is no relevant information to include in this field.
As such, parameters MUST be omitted when encoding an ML-DSA AlgorithmIdentifier.

The object identifiers for ML-DSA are defined in the NIST Computer Security Objects Register {{CSOR}}, and are reproduced here for convenience.

~~~ asn.1
sigAlgs OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
    us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) 3 }

id-ml-dsa-44 OBJECT IDENTIFIER ::= { sigAlgs 17 }

id-ml-dsa-65 OBJECT IDENTIFIER ::= { sigAlgs 18 }

id-ml-dsa-87 OBJECT IDENTIFIER ::= { sigAlgs 19 }

~~~

# ML-DSA Key Encoding

{{Section 4 of !I-D.ietf-lamps-dilithium-certificates}} describes the format of ML-DSA public keys when encoded as a part of the SubjectPublicKeyInfo type.
The signed-data content type as described in {{RFC5652}} does not encode public keys directly, but CMS content types defined by other documents do.
For example, {{?RFC5272}} describes Certificate Management over CMS, and its PKIData content utilises the SubjectPublicKeyInfo type to encode public keys for certificate requests.
When the SubjectPublicKeyInfo type is used in CMS, ML-DSA public keys MUST be encoded as described in {{!I-D.ietf-lamps-dilithium-certificates}}

{{?RFC5958}} describes the Asymmetric Key Package CMS content type, and the OneAsymmetricKey type for encoding asymmetric keypairs.
When an ML-DSA private key or keypair is encoded as a OneAsymmetricKey, it follows the description in {{Section 6 of !I-D.ietf-lamps-dilithium-certificates}}.

The ASN.1 descriptions of ML-DSA keys are repeated below for convenience.

EDNOTE: This section should reflect the content of draft-ietf-lamps-dilithium-certificates.
The ASN.1 public key definitions in that document are not yet fully expanded, so the below is a best guess based on the equivalent SLH-DSA keys.
Alternatively, draft-ietf-lamps-dilithium-certificates could reflect this document, as is the case for the SLH-DSA X.509/CMS drafts.

~~~ asn.1
pk-ml-dsa-44 PUBLIC-KEY ::= {
  IDENTIFIER id-ml-dsa-44
  -- KEY no ASN.1 wrapping --
  CERT-KEY-USAGE
    { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
  -- PRIVATE-KEY no ASN.1 wrapping -- }

pk-ml-dsa-65 PUBLIC-KEY ::= {
  IDENTIFIER id-ml-dsa-65
  -- KEY no ASN.1 wrapping --
  CERT-KEY-USAGE
    { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
  -- PRIVATE-KEY no ASN.1 wrapping -- }

pk-ml-dsa-87 PUBLIC-KEY ::= {
  IDENTIFIER id-ml-dsa-87
  -- KEY no ASN.1 wrapping --
  CERT-KEY-USAGE
    { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
  -- PRIVATE-KEY no ASN.1 wrapping -- }

ML-DSA-PublicKey ::= OCTET STRING
ML-DSA-PrivateKey ::= OCTET STRING
~~~

# Signed-data Conventions

## Pure mode vs pre-hash mode

{{RFC5652}} specifies that digital signatures for CMS are produced using a digest of the message to be signed, and the signer's private key.
At the time of publication of that RFC, all signature algorithms supported in CMS required a message digest to be calculated externally to that algorithm, which would then be supplied to the algorithm implementation when calculating and verifying signatures.
Since then, EdDSA {{?RFC8032}}, SLH-DSA {{FIPS203}} have also been standardised, and these algorithms support both a "pure" and "pre-hash" mode.
In the pre-hash mode, a message digest (the "pre-hash") is calculated separately and supplied to the signature algorithm as described above.
In the pure mode, the message to be signed or verified is instead supplied directly to the signature algorithm.
ML-DSA also supports a pre-hash and pure mode, though we follow the convention set by EdDSA in CMS {{?RFC8419}} and SLH-DSA in CMS {{?I-D.ietf-lamps-cms-sphincs-plus}} in that only the pure mode of ML-DSA is used in CMS.
That is, the pre-hash mode of ML-DSA MUST NOT be used in CMS.

## Signature generation and verification

{{RFC5652}} describes the two methods that are used to calculate and verify signatures in CMS.
One method is used when signed attributes are present in the signedAttrs field of the relevant SignerInfo, and another is used when signed attributes are absent.
Each method produces a different "message digest" to be supplied to the signature algorithm in question, but because the pure mode of ML-DSA is used, the "message digest" is in fact the entire message.
Use of signed attributes is preferred, but the conventions for signed-data without signed attributes is also described below for completeness.

EDNOTE: Would it make sense to make a stronger statement here?
For instance, that CMS implements MAY reject signatures if they don't contain signed attributes, or that generation/verification of signed-data without signed attributes SHOULD NOT be supported?
Some of the discussion around the use of context strings for new signature algorithms has highlighted the dangers here, as has Falko's paper here: https://eprint.iacr.org/2023/1801

When signed attributes are absent, ML-DSA (pure mode) signatures are computed over the content of the signed-data.
As described in {{Section 5.4 of RFC5652}}, the "content" of a signed-data is the value of the encapContentInfo eContent OCTET STRING.
The tag and length octets are not included.

When signed attributes are included, ML-DSA (pure mode) signatures are computed over a DER encoding of the SignerInfo's signedAttrs field.
As described in {{Section 5.4 of RFC5652}}, this encoding does include the tag and length octets, but an EXPLICIT SET OF tag is used rather than the IMPLICIT \[0\] tag that appears in the final message.
The signedAttrs field MUST at minimum include a content-type attribute and a message-digest attribute.
The message-digest attribute contains a hash of the content of the signed-data, where the content is as described for the absent signed attributes case above.
Recalculation of the hash value by the recipient is an important step in signature verification.
Choice of digest algorithm is up to the signer; algorithms for each parameter set are recommended below.

{{Section 4 of ?I-D.ietf-lamps-cms-sphincs-plus}} describes how, when the content of a signed-data is large, performance may be improved by including signed attributes.
This is as true for ML-DSA as it is for SLH-DSA, although ML-DSA signature generation and verification is significantly faster than SLH-DSA.

ML-DSA has a context string input that can be used to ensure that different signatures are generated for different application contexts.
When using ML-DSA as described in this document, the context string is not used.

EDNOTE: It's been suggested that the context string could be used to separate content-only/signed attributes signatures.
SLH-DSA and ML-DSA should stay in alignment here.
If not specified here, are there other ways the context string could be used, e.g. with a different algorithm identifier or a signed attribute?
If so, we could add a note to signpost that this is could appear in a future standard.

## SignerInfo content

When using ML-DSA, the fields of a SignerInfo are used as follows:

digestAlgorithm:

: Per {{Section 5.3 of RFC5652}}, the digestAlgorithm field identifies the message digest algorithm used by the signer, and any associated parameters.
To ensure collision resistance, the identified message digest algorithm SHOULD produce a hash value of a size that is at least twice the collision strength of the internal commitment hash used by ML-DSA.\\
The SHAKE hash functions defined in {{FIPS202}} are used internally by ML-DSA, and hence the combinations in {{tab-digests}} are RECOMMENDED for use with ML-DSA.
{{?RFC8702}} describes how SHAKE128 and SHAKE256 are used in CMS. The id-shake128 and id-shake256 digest algorithm identifiers are used and the parameters field MUST be omitted.

| Signature algorithm | Message digest algorithm |
| ML-DSA-44           | SHAKE128                 |
| ML-DSA-65           | SHAKE256                 |
| ML-DSA-87           | SHAKE256                 |
{: #tab-digests title="Recommended message digest algorithms for ML-DSA signature algorithms"}

signatureAlgorithm:

 : When signing a signed-data using ML-DSA, the signatureAlgorithm field MUST contain one of the ML-DSA signature algorithm OIDs, and the parameters field MUST be absent. The algorithm OID MUST be one of the following OIDs described in {{ml-dsa-algorithm-identifiers}}:

 | Signature algorithm | Algorithm Identifier OID |
 | ML-DSA-44           | id-ml-dsa-44             |
 | ML-DSA-65           | id-ml-dsa-65             |
 | ML-DSA-87           | id-ml-dsa-87             |
 {: #tab-oids title="Signature algorithm identifier OIDs for ML-DSA"}

 signature:

 : The signature field contains the signature value resulting from the use of the ML-DSA signature algorithm identified by the signatureAlgorithm field.
 The ML-DSA (pure mode) signature generation operation is specified in Section 5.2 of {{FIPS204}}, and the signature verification operation is specified in Section 5.3 of {{FIPS204}}.
 Note that {{Section 5.6 of RFC5652}} places further requirements on the successful verification of a signature.

# Security Considerations

The relevant security considerations from {{RFC5652}} apply to this document as well.

The security considerations for {{!I-D.ietf-lamps-dilithium-certificates}} are equally applicable to this document.

Security of the ML-DSA private key is critical.
Compromise of the private key will enable an adversary to forge arbitrary signatures.

By default ML-DSA signature generation uses randomness from two sources: fresh random data generated during signature generation, and precomputed random data included in the signer's private key.
This is referred to as the "hedged" variant of ML-DSA.
Inclusion of both sources of random can help mitigate against faulty random number generators and side-channel attacks.
{{FIPS204}} also permits creating deterministic signatures using just the precomputed random data in the signer's private key.
The signer SHOULD NOT use the deterministic variant of ML-DSA on platforms where side-channel attacks are a concern.


# IANA Considerations

IANA is requested to assign an object identifier for id-mod-ml-dsa-2024, for the ASN.1 module identifier found in {{asn1}}.
This should be allocated in the "SMI Security for PKIX Module Identifier" registry (1.3.6.1.5.5.7.0).


# Acknowledgments

TODO acknowledgements.


--- back

# ASN.1 Module {#asn1}

~~~ asn.1
ML-DSA-Module-2024
  { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
    id-smime(16) id-mod(0) id-mod-ml-dsa-2024(TBD) }

DEFINITIONS IMPLICIT TAGS ::= BEGIN

EXPORTS ALL;

IMPORTS PUBLIC-KEY, SIGNATURE-ALGORITHM, SMIME-CAPS
  FROM AlgorithmInformation-2009 -- in [RFC5911]
  { iso(1) identified-organization(3) dod(6) internet(1)
    security(5) mechanisms(5) pkix(7) id-mod(0)
    id-mod-algorithmInformation-02(58) } ;

--
-- Object Identifiers
--

sigAlgs OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16)
    us(840) organization(1) gov(101) csor(3) nistAlgorithms(4) 3 }

id-ml-dsa-44 OBJECT IDENTIFIER ::= { sigAlgs 17 }

id-ml-dsa-65 OBJECT IDENTIFIER ::= { sigAlgs 18 }

id-ml-dsa-87 OBJECT IDENTIFIER ::= { sigAlgs 19 }

--
-- Signature Algorithm Identifiers
--

sa-ml-dsa-44 SIGNATURE-ALGORITHM ::= {
  IDENTIFIER id-ml-dsa-44
  PARAMS ARE absent
  PUBLIC-KEYS { pk-ml-dsa-44 }
  SMIME-CAPS { IDENTIFIED BY id-ml-dsa-44 } }

sa-ml-dsa-65 SIGNATURE-ALGORITHM ::= {
  IDENTIFIER id-ml-dsa-65
  PARAMS ARE absent
  PUBLIC-KEYS { pk-ml-dsa-65 }
  SMIME-CAPS { IDENTIFIED BY id-ml-dsa-65 } }

sa-ml-dsa-87 SIGNATURE-ALGORITHM ::= {
  IDENTIFIER id-ml-dsa-87
  PARAMS ARE absent
  PUBLIC-KEYS { pk-ml-dsa-87 }
  SMIME-CAPS { IDENTIFIED BY id-ml-dsa-87 } }

--
-- Public Keys
--

pk-ml-dsa-44 PUBLIC-KEY ::= {
  IDENTIFIER id-ml-dsa-44
  -- KEY no ASN.1 wrapping --
  CERT-KEY-USAGE
    { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
  -- PRIVATE-KEY no ASN.1 wrapping -- }

pk-ml-dsa-65 PUBLIC-KEY ::= {
  IDENTIFIER id-ml-dsa-65
  -- KEY no ASN.1 wrapping --
  CERT-KEY-USAGE
    { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
  -- PRIVATE-KEY no ASN.1 wrapping -- }

pk-ml-dsa-87 PUBLIC-KEY ::= {
  IDENTIFIER id-ml-dsa-87
  -- KEY no ASN.1 wrapping --
  CERT-KEY-USAGE
    { digitalSignature, nonRepudiation, keyCertSign, cRLSign }
  -- PRIVATE-KEY no ASN.1 wrapping -- }

ML-DSA-PublicKey ::= OCTET STRING

ML-DSA-PrivateKey ::= OCTET STRING


--
-- Expand the signature algorithm set used by CMS [RFC5911]
--

SignatureAlgorithmSet SIGNATURE-ALGORITHM ::= {
  sa-ml-dsa-44 |
  sa-ml-dsa-65 |
  sa-ml-dsa-87,
  ... }

SMimeCaps SMIME-CAPS ::= {
  sa-ml-dsa-44.&smimeCaps |
  sa-ml-dsa-65.&smimeCaps |
  sa-ml-dsa-87.&smimeCaps,
  ... }

END
~~~
