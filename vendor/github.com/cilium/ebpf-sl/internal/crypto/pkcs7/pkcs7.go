package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

var (
	// RFC 5652, section 4: Data Content Type
	oidPKCS7Data = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	// RFC 5652, section 5.1: SignedData type
	oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	// RFC8017, Appendix 3: ASN.1 Module
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	// RFC 3279, section 2.2.3: ECDSA Signature Algorithm
	oidECDSAWithSHA1 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}

	// RFC5758, section 3.2:  ECDSA Signature Algorithm
	oidECDSAWithSHA2   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3}
	oidECDSAWithSHA256 = append(oidECDSAWithSHA2, 2)
	oidECDSAWithSHA384 = append(oidECDSAWithSHA2, 3)
	oidECDSAWithSHA512 = append(oidECDSAWithSHA2, 4)

	// NIST CSOR ECDSA with SHA-3 family
	oidNistSigAlgos      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3}
	oidECDSAWithSHA3_256 = append(oidNistSigAlgos, 10)
	oidECDSAWithSHA3_384 = append(oidNistSigAlgos, 11)
	oidECDSAWithSHA3_512 = append(oidNistSigAlgos, 12)

	// NIST CSOR ML-DSA
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	// RFC3370, section 2.1: SHA-1
	oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

	// NIST CSOR SHA-2 family
	oidCTORHashAlgos = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2}
	oidSHA256        = append(oidCTORHashAlgos, 1)
	oidSHA384        = append(oidCTORHashAlgos, 2)
	oidSHA512        = append(oidCTORHashAlgos, 3)
	oidSHA3_256      = append(oidCTORHashAlgos, 8)
	oidSHA3_384      = append(oidCTORHashAlgos, 9)
	oidSHA3_512      = append(oidCTORHashAlgos, 10)

	asn1NullRawValue = asn1.RawValue{Tag: asn1.TagNull}

	cmsVersion = 3
)

// RFC 5652, section 3: General syntax
//
//	ContentInfo ::= SEQUENCE {
//	  contentType ContentType,
//	  content [0] EXPLICIT ANY DEFINED BY contentType }
//
//	ContentType ::= OBJECT IDENTIFIER
type pkcs7ContentInfo struct {
	// In out case one of [oidPKCS7Data] or [oidPKCS7SignedData] is expected.
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

// RFC 5652, section 5.1: SignedData type
//
//	SignedData ::= SEQUENCE {
//	  version CMSVersion,
//	  digestAlgorithms DigestAlgorithmIdentifiers,
//	  encapContentInfo EncapsulatedContentInfo,
//	  certificates [0] IMPLICIT CertificateSet OPTIONAL,
//	  crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//	  signerInfos SignerInfos }

// SignerInfos ::= SET OF SignerInfo
type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo pkcs7ContentInfo
	// certificates and crls are not used in this implementation.
	SignerInfos []pkcs7SignerInfo `asn1:"set"`
}

// RFC 5652, section 5.3: SignerInfo type
//
//	SignerInfo ::= SEQUENCE {
//	  version CMSVersion,
//	  sid SignerIdentifier,
//	  digestAlgorithm DigestAlgorithmIdentifier,
//	  signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//	  signatureAlgorithm SignatureAlgorithmIdentifier,
//	  signature SignatureValue,
//	  unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
//
//	SignerIdentifier ::= CHOICE {
//	  issuerAndSerialNumber IssuerAndSerialNumber,
//	  subjectKeyIdentifier [0] SubjectKeyIdentifier }
//
//	SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
//
//	UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
//
//	Attribute ::= SEQUENCE {
//	  attrType OBJECT IDENTIFIER,
//	  attrValues SET OF AttributeValue }
//
//	AttributeValue ::= ANY
//
//	SignatureValue ::= OCTET STRING
type pkcs7SignerInfo struct {
	Version         int
	SubjectID       asn1.RawValue
	DigestAlgorithm pkix.AlgorithmIdentifier
	// signedAttrs are not used in this implementation.
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	// unsignedAttrs are not used in this implementation.
}

type SignOptions struct {
	// The hash function used to hash the instructions before signing.
	// Defaults to SHA3_256 if not specified.
	Hash crypto.Hash
	// The certificate used to sign the content. This must be a valid X.509 certificate.
	Certificate *x509.Certificate
	// The private key used to sign the content. This must correspond to the public key in the certificate.
	PrivateKey crypto.PrivateKey
}

// Sign returns a PKCS#7 detached signature of the given content using the provided private key and certificate.
func Sign(content []byte, opts SignOptions) ([]byte, error) {
	// Extract the subject key identifier from the certificate to use as the signer identifier.
	subjectKeyID, err := getSubjectKeyIdentifier(opts.Certificate)
	if err != nil {
		return nil, err
	}

	// Default to SHA3-256 if no hash function is specified.
	if opts.Hash == 0 {
		opts.Hash = crypto.SHA3_256
	}

	var digestAlgoOID asn1.ObjectIdentifier
	switch opts.Hash {
	// Leave out SHA-1, it's outdated and subject to collision attacks.
	case crypto.SHA256:
		digestAlgoOID = oidSHA256
	case crypto.SHA384:
		digestAlgoOID = oidSHA384
	case crypto.SHA512:
		digestAlgoOID = oidSHA512
	case crypto.SHA3_256:
		digestAlgoOID = oidSHA3_256
	case crypto.SHA3_384:
		digestAlgoOID = oidSHA3_384
	case crypto.SHA3_512:
		digestAlgoOID = oidSHA3_512
	default:
		return nil, fmt.Errorf("unsupported hash function: %v", opts.Hash)
	}

	// Take the digest of the content to sign using the specified hash function.
	h := opts.Hash.New()
	h.Write(content)
	digest := h.Sum(nil)

	var signatureAlgoOID asn1.ObjectIdentifier
	switch privkey := opts.PrivateKey.(type) {
	case *rsa.PrivateKey:
		signatureAlgoOID = oidRSAEncryption
		pubKey, ok := opts.Certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key in the certificate is not an RSA public key")
		}

		if !pubKey.Equal(privkey.Public()) {
			return nil, fmt.Errorf("RSA private key does not match the public key in the certificate")
		}

	case *ecdsa.PrivateKey:
		// The signature algorithm for ECDSA always includes a hash function.
		// But in practice the kernel treats all ECDSA signatures the same, so we just always use SHA3-256.
		signatureAlgoOID = oidECDSAWithSHA3_256

		pubKey, ok := opts.Certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key in the certificate is not an ECDSA public key")
		}

		if !pubKey.Equal(&privkey.PublicKey) {
			return nil, fmt.Errorf("ECDSA private key does not match the public key in the certificate")
		}

	case *mldsa.PrivateKey:
		switch privkey.PublicKey().Parameters() {
		case mldsa.MLDSA44():
			signatureAlgoOID = oidMLDSA44
		case mldsa.MLDSA65():
			signatureAlgoOID = oidMLDSA65
		case mldsa.MLDSA87():
			signatureAlgoOID = oidMLDSA87
		default:
			return nil, fmt.Errorf("unsupported ML-DSA parameter set: %v", privkey.PublicKey().Parameters())
		}

		pubKey, ok := opts.Certificate.PublicKey.(*mldsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key in the certificate is not an ML-DSA public key")
		}

		if !pubKey.Equal(privkey.PublicKey()) {
			return nil, fmt.Errorf("ML-DSA private key does not match the public key in the certificate")
		}

		// ML-DSA signatures are always computed over the raw content, not a digest.
		// So we override the digest to be the content itself and set the hash function to 0 to indicate that no hashing is done.
		digest = content
		opts.Hash = 0

	default:
		return nil, fmt.Errorf("unsupported private key type: %T", opts.PrivateKey)
	}

	signer := opts.PrivateKey.(crypto.Signer)
	signature, err := signer.Sign(rand.Reader, digest[:], opts.Hash)
	if err != nil {
		return nil, fmt.Errorf("sign content digest: %w", err)
	}

	// Construct a signed data message
	signedDataDER, err := asn1.Marshal(pkcs7SignedData{
		// We use version 3, this indicates we include the subjectKeyIdentifier in the signer info.
		Version: cmsVersion,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{
			Algorithm: digestAlgoOID,
		}},
		// The content we are signing is the raw data.
		EncapContentInfo: pkcs7ContentInfo{
			ContentType: oidPKCS7Data,
		},
		// List of signers, in our case just one.
		SignerInfos: []pkcs7SignerInfo{{
			Version: cmsVersion,
			// The subject key ID from the certificate is used to identify the signer.
			SubjectID: asn1.RawValue{
				Class: asn1.ClassContextSpecific,
				Tag:   0,
				Bytes: subjectKeyID,
			},
			DigestAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: digestAlgoOID,
			},
			// We used RSA to sign the digest.
			SignatureAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  signatureAlgoOID,
				Parameters: asn1NullRawValue,
			},
			// The actual signature of the content digest.
			Signature: signature,
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal signed data: %w", err)
	}

	// Wrap the signed data in a ContentInfo structure, which is the top-level structure of a PKCS#7 message.
	pkcs7Signature, err := asn1.Marshal(pkcs7ContentInfo{
		ContentType: oidPKCS7SignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedDataDER,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("marshal content info: %w", err)
	}

	return pkcs7Signature, nil
}

func Verify(certificate *x509.Certificate, content, signature []byte) error {
	var contentInfo pkcs7ContentInfo
	rest, err := asn1.Unmarshal(signature, &contentInfo)
	if err != nil {
		return fmt.Errorf("parse content info: %w", err)
	}
	if len(rest) != 0 {
		return errors.New("pkcs7 signature has trailing data")
	}
	if !contentInfo.ContentType.Equal(oidPKCS7SignedData) {
		return fmt.Errorf("unexpected content type %v", contentInfo.ContentType)
	}
	if contentInfo.Content.Class != asn1.ClassContextSpecific || contentInfo.Content.Tag != 0 {
		return errors.New("pkcs7 signed data missing explicit content wrapper")
	}

	var signedData pkcs7SignedData
	rest, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return fmt.Errorf("parse signed data: %w", err)
	}
	if len(rest) != 0 {
		return errors.New("signed data has trailing data")
	}
	if signedData.Version != cmsVersion {
		return fmt.Errorf("unexpected signed data version %d", signedData.Version)
	}
	if !signedData.EncapContentInfo.ContentType.Equal(oidPKCS7Data) {
		return fmt.Errorf("unexpected encapsulated content type %v", signedData.EncapContentInfo.ContentType)
	}
	if len(signedData.SignerInfos) != 1 {
		return fmt.Errorf("expected 1 signer info, got %d", len(signedData.SignerInfos))
	}

	signer := signedData.SignerInfos[0]
	if signer.Version != cmsVersion {
		return fmt.Errorf("unexpected signer info version %d", signer.Version)
	}
	if signer.SubjectID.Class != asn1.ClassContextSpecific || signer.SubjectID.Tag != 0 {
		return errors.New("unsupported signer identifier")
	}

	var digestHash crypto.Hash
	switch {
	case signer.DigestAlgorithm.Algorithm.Equal(oidSHA1):
		digestHash = crypto.SHA1
	case signer.DigestAlgorithm.Algorithm.Equal(oidSHA256):
		digestHash = crypto.SHA256
	case signer.DigestAlgorithm.Algorithm.Equal(oidSHA384):
		digestHash = crypto.SHA384
	case signer.DigestAlgorithm.Algorithm.Equal(oidSHA512):
		digestHash = crypto.SHA512
	case signer.DigestAlgorithm.Algorithm.Equal(oidSHA3_256):
		digestHash = crypto.SHA3_256
	case signer.DigestAlgorithm.Algorithm.Equal(oidSHA3_384):
		digestHash = crypto.SHA3_384
	case signer.DigestAlgorithm.Algorithm.Equal(oidSHA3_512):
		digestHash = crypto.SHA3_512
	default:
		return fmt.Errorf("unsupported digest algorithm %v", signer.DigestAlgorithm.Algorithm)
	}

	var pubKey crypto.PublicKey
	switch {
	case signer.SignatureAlgorithm.Algorithm.Equal(oidRSAEncryption):
		var ok bool
		pubKey, ok = certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("algo mismatch, signature is RSA, cannot use public key type %T", certificate.PublicKey)
		}
	case signer.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA1),
		signer.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA256),
		signer.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA384),
		signer.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA512),
		signer.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA3_256),
		signer.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA3_384),
		signer.SignatureAlgorithm.Algorithm.Equal(oidECDSAWithSHA3_512):
		var ok bool
		pubKey, ok = certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("algo mismatch, signature is ECDSA, cannot use public key type %T", certificate.PublicKey)
		}
	case signer.SignatureAlgorithm.Algorithm.Equal(oidMLDSA44),
		signer.SignatureAlgorithm.Algorithm.Equal(oidMLDSA65),
		signer.SignatureAlgorithm.Algorithm.Equal(oidMLDSA87):
		var ok bool
		pubKey, ok = certificate.PublicKey.(*mldsa.PublicKey)
		if !ok {
			return fmt.Errorf("algo mismatch, signature is ML-DSA, cannot use public key type %T", certificate.PublicKey)
		}
	default:
		return fmt.Errorf("unsupported signature algorithm %v", signer.SignatureAlgorithm.Algorithm)
	}

	expectedSubjectKeyID, err := getSubjectKeyIdentifier(certificate)
	if err != nil {
		return err
	}
	if !bytes.Equal(signer.SubjectID.Bytes, expectedSubjectKeyID) {
		return errors.New("signer identifier does not match certificate")
	}

	h := digestHash.New()
	h.Write(content)
	digest := h.Sum(nil)

	switch pubKey := pubKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pubKey, digestHash, digest[:], signer.Signature); err != nil {
			return fmt.Errorf("verify signature: %w", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pubKey, digest[:], signer.Signature) {
			return errors.New("verify signature: invalid ECDSA signature")
		}
	case *mldsa.PublicKey:
		if err := mldsa.Verify(pubKey, content, signer.Signature, nil); err != nil {
			return errors.New("verify signature: invalid ML-DSA signature")
		}
	default:
		return fmt.Errorf("unsupported certificate public key type %T", pubKey)
	}

	return nil
}

func getSubjectKeyIdentifier(cert *x509.Certificate) ([]byte, error) {
	if len(cert.SubjectKeyId) > 0 {
		return cert.SubjectKeyId, nil
	}

	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	var publicKeyInfo struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &publicKeyInfo); err != nil {
		return nil, fmt.Errorf("parse subject public key info: %w", err)
	}

	subjectKeyID := sha1.Sum(publicKeyInfo.SubjectPublicKey.Bytes)
	return subjectKeyID[:], nil
}
