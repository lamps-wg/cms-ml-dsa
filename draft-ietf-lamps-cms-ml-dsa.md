---
title: "Use of the ML-DSA Signature Algorithm in the Cryptographic Message Syntax (CMS)"
abbrev: "ML-DSA in the CMS"
category: std

docname: draft-ietf-lamps-cms-ml-dsa-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Limited Additional Mechanisms for PKIX and SMIME"
keyword:
  - cms
  - ml-dsa
  - dilithium
venue:
  group: "Limited Additional Mechanisms for PKIX and SMIME"
  type: "Working Group"
  mail: "spasm@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spasm/"
  github: "lamps-wg/cms-ml-dsa"
  latest: "https://lamps-wg.github.io/cms-ml-dsa/draft-ietf-lamps-cms-ml-dsa.html"

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
  FIPS204: DOI.10.6028/NIST.FIPS.204
  CSOR:
    target: https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
    title: Computer Security Objects Register
    author:
      name: National Institute of Standards and Technology
      ins: NIST
    date: 2024-08-20
  RFC5652:

informative:
  FIPS180: DOI.10.6028/NIST.FIPS.180-4
  FIPS205: DOI.10.6028/NIST.FIPS.205
  RFC5911:
  X680:
    target: https://www.itu.int/rec/T-REC-X.680
    title: "Information Technology - Abstract Syntax Notation One (ASN.1): Specification of basic notation. ITU-T Recommendation X.680 (2021) | ISO/IEC 8824-1:2021."
    author:
      org: ITU-T
    date: February 2021
  KPLG2024:
    target: https://ia.cr/2024/138
    title: "Correction Fault Attacks on Randomized CRYSTALS-Dilithium"
    author:
      -
        ins: E. Krahmer
      -
        ins: P. Pessl
      -
        ins: G. Land
      -
        ins: T. Güneysu
    date: 2024
    format:
      PDF: https://eprint.iacr.org/2024/138.pdf
  WNGD2023:
    target: https://ia.cr/2023/1931
    title: "Single-Trace Side-Channel Attacks on CRYSTALS-Dilithium: Myth or Reality?"
    author:
      -
        ins: R. Wang
      -
        ins: K. Ngo
      -
        ins: J. Gärtner
      -
        ins: E. Dubrova
    date: 2023
    format:
      PDF: https://eprint.iacr.org/2023/1931.pdf
---

--- abstract

The Module-Lattice-Based Digital Signature Algorithm (ML-DSA), as defined by NIST in FIPS 204, is a post-quantum digital signature scheme that aims to be secure against an adversary in possession of a Cryptographically Relevant Quantum Computer (CRQC).
This document specifies the conventions for using the ML-DSA signature algorithm with the Cryptographic Message Syntax (CMS).
In addition, the algorithm identifier and public key syntax are provided.


--- middle

# Introduction

The Module-Lattice-Based Digital Signature Algorithm (ML-DSA) is a digital signature algorithm standardised by the US National Institute of Standards and Technology (NIST) as part of their post-quantum cryptography standardisation process.
It is intended to be secure against both "traditional" cryptographic attacks, as well as attacks utilising a quantum computer.
It offers smaller signatures and significantly faster runtimes than SLH-DSA {{FIPS205}}, an alternative post-quantum signature algorithm also standardised by NIST.
This document specifies the use of the ML-DSA in the CMS at three security levels: ML-DSA-44, ML-DSA-65, and ML-DSA-87.  See {{Appendix B of I-D.ietf-lamps-dilithium-certificates}} for more information on the security levels and key sizes of ML-DSA.

Prior to standardisation, ML-DSA was known as Dilithium.  ML-DSA and Dilithium are not compatible.

For each of the ML-DSA parameter sets, an algorithm identifier OID has been specified.

{{FIPS204}} also specifies a pre-hashed variant of ML-DSA, called HashML-DSA.
Use of HashML-DSA in the CMS is not specified in this document.
See {{pure-vs-pre-hash}} for more details.


## Conventions and Definitions

{::boilerplate bcp14-tagged}


# ML-DSA Algorithm Identifiers {#ml-dsa-algorithm-identifiers}

Many ASN.1 data structure types use the AlgorithmIdentifier type to identify cryptographic algorithms.
In the CMS, AlgorithmIdentifiers are used to identify ML-DSA signatures in the signed-data content type.
They may also appear in X.509 certificates used to verify those signatures.
The same AlgorithmIdentifiers are used to identify ML-DSA public keys and signature algorithms.
{{?I-D.ietf-lamps-dilithium-certificates}} describes the use of ML-DSA in X.509 certificates.
The AlgorithmIdentifier type is defined as follows:

~~~ asn.1
AlgorithmIdentifier{ALGORITHM-TYPE, ALGORITHM-TYPE:AlgorithmSet} ::=
        SEQUENCE {
            algorithm   ALGORITHM-TYPE.&id({AlgorithmSet}),
            parameters  ALGORITHM-TYPE.
                   &Params({AlgorithmSet}{@algorithm}) OPTIONAL
        }
~~~

<aside markdown="block">
  NOTE: The above syntax is from {{RFC5911}} and is compatible with the
  2021 ASN.1 syntax {{X680}}. See {{?RFC5280}} for the 1988 ASN.1 syntax.
</aside>

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

# Signed-data Conventions

## Pure mode vs pre-hash mode {#pure-vs-pre-hash}

{{RFC5652}} specifies that digital signatures for CMS are produced using a digest of the message to be signed, and the signer's private key.
At the time of publication of that RFC, all signature algorithms supported in the CMS required a message digest to be calculated externally to that algorithm, which would then be supplied to the algorithm implementation when calculating and verifying signatures.
Since then, EdDSA {{?RFC8032}}, SLH-DSA {{FIPS205}} and ML-DSA have also been standardised, and these algorithms support both a "pure" and "pre-hash" mode.
In the pre-hash mode, a message digest (the "pre-hash") is calculated separately and supplied to the signature algorithm as described above.
In the pure mode, the message to be signed or verified is instead supplied directly to the signature algorithm.
When EdDSA {{?RFC8419}} and SLH-DSA {{?I-D.ietf-lamps-cms-sphincs-plus}} are used with CMS, only the pure mode of those algorithms is specified.
This is because in most situations, CMS signatures are computed over a set of signed attributes that contain a hash of the content, rather than being computed over the message content itself.
Since signed attributes are typically small, use of pre-hash modes in the CMS wouldn't significantly reduce the size of the data to be signed, and hence offers no benefit.
This document follows that convention and does not specify the use of ML-DSA's pre-hash mode ("HashML-DSA") in the CMS.

## Signature generation and verification

{{RFC5652}} describes the two methods that are used to calculate and verify signatures in the CMS.
One method is used when signed attributes are present in the signedAttrs field of the relevant SignerInfo, and another is used when signed attributes are absent.
Each method produces a different "message digest" to be supplied to the signature algorithm in question, but because the pure mode of ML-DSA is used, the "message digest" is in fact the entire message.
Use of signed attributes is preferred, but the conventions for signed-data without signed attributes is also described below for completeness.

When signed attributes are absent, ML-DSA (pure mode) signatures are computed over the content of the signed-data.
As described in {{Section 5.4 of RFC5652}}, the "content" of a signed-data is the value of the encapContentInfo eContent OCTET STRING.
The tag and length octets are not included.

When signed attributes are included, ML-DSA (pure mode) signatures are computed over the complete DER encoding of the SignedAttrs value contained in the SignerInfo's signedAttrs field.
As described in {{Section 5.4 of RFC5652}}, this encoding includes the tag and length octets, but an EXPLICIT SET OF tag is used rather than the IMPLICIT \[0\] tag that appears in the final message.
The signedAttrs field MUST at minimum include a content-type attribute and a message-digest attribute.
The message-digest attribute contains a hash of the content of the signed-data, where the content is as described for the absent signed attributes case above.
Recalculation of the hash value by the recipient is an important step in signature verification.

{{Section 4 of ?I-D.ietf-lamps-cms-sphincs-plus}} describes how, when the content of a signed-data is large, performance may be improved by including signed attributes.
This is as true for ML-DSA as it is for SLH-DSA, although ML-DSA signature generation and verification is significantly faster than SLH-DSA.

ML-DSA has a context string input that can be used to ensure that different signatures are generated for different application contexts.
When using ML-DSA as specified in this document, the context string is set to the empty string.

## SignerInfo content

When using ML-DSA, the fields of a SignerInfo are used as follows:

digestAlgorithm:

: Per {{Section 5.3 of RFC5652}}, the digestAlgorithm field identifies the message digest algorithm used by the signer, and any associated parameters.
Each ML-DSA parameter set has a collision strength parameter, represented by the &lambda; (lambda) symbol in {{FIPS204}}.
When signers utilise signed attributes, their choice of digest algorithm may impact the overall security level of their signature.
Selecting a digest algorithm that offers &lambda; bits of security strength against second preimage attacks and collision attacks is sufficient to meet the security level offered by a given parameter set, so long as the digest algorithm produces at least 2 * &lambda; bits of output.
The overall security strength offered by an ML-DSA signature calculated over signed attributes is the floor of the digest algorithm's strength and the strength of the ML-DSA parameter set.
Verifiers MAY reject a signature if the signer's choice of digest algorithm does not meet the security requirements of their choice of ML-DSA parameter set.
{{ml-dsa-digest-algs}} shows appropriate SHA-2 and SHA-3 digest algorithms for each parameter set.

: SHA-512 {{FIPS180}} MUST be supported for use with the variants of ML-DSA in this document.
SHA-512 is suitable for all ML-DSA parameter sets and provides an interoperable option for legacy CMS implementations that wish to migrate to use post-quantum cryptography, but that may not support use of SHA-3 derivatives at the CMS layer.
However, other hash functions MAY also be supported; in particular, SHAKE256 SHOULD be supported, as this is the digest algorithm used internally in ML-DSA.
When SHA-512 is used, the id-sha512 {{!RFC5754}} digest algorithm identifier is used and the parameters field MUST be omitted.
When SHAKE256 is used, the id-shake256 {{!RFC8702}} digest algorithm identifier is used and the parameters field MUST be omitted.
SHAKE256 produces 512 bits of output when used as a message digest algorithm in the CMS.

: When signing using ML-DSA without including signed attributes, the algorithm specified in the digestAlgorithm field has no meaning, as ML-DSA computes signatures over entire messages rather than externally computed digests.
As such, the considerations above and in {{ml-dsa-digest-algs}} do not apply.
Nonetheless, in this case implementations MUST specify SHA-512 as the digestAlgorithm in order to minimise the likelihood of an interoperability failure.
When processing a SignerInfo signed using ML-DSA, if no signed attributes are present, implementations MUST ignore the content of the digestAlgorithm field.

 | Signature algorithm | Digest Algorithms                                                           |
 | ML-DSA-44           | SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 |
 | ML-DSA-65           | SHA-384, SHA-512, SHA3-384, SHA3-512, SHAKE256                              |
 | ML-DSA-87           | SHA-512, SHA3-512, SHAKE256                                                 |
 {: #ml-dsa-digest-algs title="Suitable digest algorithms for ML-DSA"}

signatureAlgorithm:

 : The signatureAlgorithm field MUST contain one of the ML-DSA signature algorithm OIDs, and the parameters field MUST be absent. The algorithm OID MUST be one of the following OIDs described in {{ml-dsa-algorithm-identifiers}}:

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

The security considerations in {{RFC5652}} and {{!I-D.ietf-lamps-dilithium-certificates}} apply to this specification.

Security of the ML-DSA private key is critical.
Compromise of the private key will enable an adversary to forge arbitrary signatures.

ML-DSA depends on high quality random numbers that are suitable for use in cryptography.
The use of inadequate pseudo-random number generators (PRNGs) to generate such values can significantly undermine the security properties offered by a cryptographic algorithm.
For instance, an attacker may find it much easier to reproduce the PRNG environment that produced any private keys, searching the resulting small set of possibilities, rather than brute force searching the whole key space.
The generation of random numbers of a sufficient level of quality for use in cryptography is difficult; see Section 3.6.1 of {{FIPS204}} for some additional information.

By default, ML-DSA signature generation uses randomness from two sources: fresh random data generated during signature generation, and precomputed random data included in the signer's private key.
This is referred to as the "hedged" variant of ML-DSA.
Inclusion of both sources of random can help mitigate against faulty random number generators, side-channel attacks and fault attacks.
{{FIPS204}} also permits creating deterministic signatures using just the precomputed random data in the signer's private key.
The same verification algorithm is used to verify both hedged and deterministic signatures, so this choice does not affect interoperability.
The signer SHOULD NOT use the deterministic variant of ML-DSA on platforms where side-channel attacks or fault attacks are a concern.
Side channel attacks and fault attacks against ML-DSA are an active area of research {{WNGD2023}} {{KPLG2024}}.
Future protection against these styles of attack may involve interoperable changes to the implementation of ML-DSA's internal functions.
Implementers SHOULD consider implementing such protection measures if it would be beneficial for their particular use cases.

To avoid algorithm substitution attacks, the CMSAlgorithmProtection attribute defined in {{!RFC6211}} SHOULD be included in signed attributes.

# Operational Considerations
If ML-DSA signing is implemented in a hardware device such as hardware security module (HSM) or portable cryptographic token, implementers might want to avoid sending the full content to the device for performance reasons.
By including signed attributes, which necessarily include the message-digest attribute and the content-type attribute as described in Section 5.3 of {{RFC5652}}, the much smaller set of signed attributes are sent to the device for signing.

Additionally, the pure variant of ML-DSA does support a form of pre-hash via external calculation of the &mu; (mu) "message representative" value described in Section 6.2 of {{FIPS204}}.
This value may "optionally be computed in a different cryptographic module" and supplied to the hardware device, rather than requiring the entire message to be transmitted.
Appendix D of {{?I-D.ietf-lamps-dilithium-certificates}} describes use of external &mu; calculations in further detail.

# IANA Considerations

For the ASN.1 module found in {{asn1}}, IANA is requested to assign an object identifier for the module identifier (TBD1) with a description of "id-mod-ml-dsa-2024".
This should be allocated in the "SMI Security for S/MIME Module Identifier" registry (1.2.840.113549.1.9.16.0).


# Acknowledgments

The authors would like to thank the following people for their contributions and reviews that helped shape this document: Viktor Dukhovni, Russ Housley, Panos Kampanakis, Mike Ounsworth, Falko Strenzke, Sean Turner, and Wei-Jun Wang.

This document was heavily influenced by {{?RFC8419}}, {{?I-D.ietf-lamps-cms-sphincs-plus}}, and {{?I-D.ietf-lamps-dilithium-certificates}}.
Thanks go to the authors of those documents.


--- back

# ASN.1 Module {#asn1}

<aside markdown="block">
RFC EDITOR: Please replace the reference to [I-D.ietf-lamps-dilithium-certificates]
in the ASN.1 module below with a reference the corresponding published RFC.
</aside>

~~~ asn.1
<CODE BEGINS>
{::include ML-DSA-Module-2024.asn}
<CODE ENDS>
~~~

# Examples

This appendix contains example signed-data encodings.
They can be verified using the example public keys and certificates specified in Appendix C of {{?I-D.ietf-lamps-dilithium-certificates}}.

The following is an example of a signed-data with a single ML-DSA-44 signer, with signed attributes included:

~~~
{::include ./examples/mldsa44-signed-attrs.pem}
~~~

~~~
{::include ./examples/mldsa44-signed-attrs.txt}
~~~

The following is an example of a signed-data with a single ML-DSA-65 signer, with signed attributes included:

~~~
{::include ./examples/mldsa65-signed-attrs.pem}
~~~

~~~
{::include ./examples/mldsa65-signed-attrs.txt}
~~~

The following is an example of a signed-data with a single ML-DSA-87 signer, with signed attributes included:

~~~
{::include ./examples/mldsa87-signed-attrs.pem}
~~~

~~~
{::include ./examples/mldsa87-signed-attrs.txt}
~~~
