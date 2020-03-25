package eu.europa.esig.dss.spi.x509;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;

/**
 * Represents a source of certificates embedded in a token (signature, timestamp, ocsp response)
 *
 */
@SuppressWarnings("serial")
public abstract class TokenCertificateSource extends CommonCertificateSource {
	
	private final Map<CertificateToken, List<CertificateOrigin>> certificateOrigins = new HashMap<>();

	private final Map<CertificateRef, List<CertificateRefOrigin>> certificateRefOrigins = new HashMap<>();
	
	private final CertificateTokenRefMatcher certificateMatcher = new CertificateTokenRefMatcher();

	protected TokenCertificateSource() {
		super();
	}

	protected TokenCertificateSource(final CertificatePool certPool) {
		super(certPool);
	}
	
	/**
	 * Adds a {@code CertificateToken} with its {@code CertificateOrigin}
	 * 
	 * @param certificate the certificate to be added
	 * @param origin      the origin of the certificate
	 */
	protected void addCertificate(CertificateToken certificate, CertificateOrigin origin) {
		Objects.requireNonNull(certificate, "The certificate cannot be null");
		Objects.requireNonNull(origin, "The origin cannot be null");
		certificateOrigins.computeIfAbsent(certificate, k -> new ArrayList<>()).add(origin);
		// TODO remove ?
		addCertificate(certificate);
	}

	/**
	 * Adds a {@code CertificateRef} with its {@code CertificateRefOrigin}
	 * 
	 * @param certificateRef the certificate reference to be added
	 * @param origin         the origin of the certificate reference
	 */
	protected void addCertificateRef(CertificateRef certificateRef, CertificateRefOrigin origin) {
		Objects.requireNonNull(certificateRef, "The certificateRef cannot be null");
		Objects.requireNonNull(origin, "The origin cannot be null");
		certificateRefOrigins.computeIfAbsent(certificateRef, k -> new ArrayList<>()).add(origin);
	}

	/**
	 * Returns list of {@link CertificateRef}s found for the given
	 * {@code certificateToken}
	 * 
	 * @param certificateToken {@link CertificateToken} to find references for
	 * @return list of {@link CertificateRef}s
	 */
	public List<CertificateRef> getReferencesForCertificateToken(CertificateToken certificateToken) {
		List<CertificateRef> result = new ArrayList<>();
		for (CertificateRef certificateRef : certificateRefOrigins.keySet()) {
			if (certificateMatcher.match(certificateToken, certificateRef)) {
				result.add(certificateRef);
			}
		}
		return result;
	}

	/**
	 * Returns list of {@link CertificateToken}s for the provided {@link CertificateRef}s
	 * @param certificateRefs list of {@link CertificateRef}s
	 * @return list of {@link CertificateToken}s
	 */
	public List<CertificateToken> findTokensFromRefs(List<CertificateRef> certificateRefs) {
		List<CertificateToken> result = new ArrayList<>();
		for (CertificateToken certificateToken : certificateOrigins.keySet()) {
			for (CertificateRef certificateRef : certificateRefs) {
				if (certificateMatcher.match(certificateToken, certificateRef)) {
					result.add(certificateToken);
				}
			}
		}
		return result;
	}
	
	/**
	 * Returns a Set of all certificate references
	 * 
	 * @return a Set of {@link CertificateRef}s
	 */
	public Set<CertificateRef> getAllCertificateRefs() {
		return certificateRefOrigins.keySet();
	}
	
	/**
	 * Returns a list of orphan certificate refs
	 * @return list of {@link CertificateRef}s
	 */
	public List<CertificateRef> getOrphanCertificateRefs() {
		List<CertificateRef> result = new ArrayList<>();
		for (CertificateRef certificateRef : certificateRefOrigins.keySet()) {
			if (isOrphan(certificateRef)) {
				result.add(certificateRef);
			}
		}
		return result;
	}

	private boolean isOrphan(CertificateRef certificateRef) {
		for (CertificateToken certificateToken : certificateOrigins.keySet()) {
			if (certificateMatcher.match(certificateToken, certificateRef)) {
				return false;
			}
		}
		return true;
	}

	protected List<CertificateToken> getCertificateTokensByOrigin(CertificateOrigin origin) {
		List<CertificateToken> result = new ArrayList<>();
		for (Entry<CertificateToken, List<CertificateOrigin>> entry : certificateOrigins.entrySet()) {
			List<CertificateOrigin> currentOrigins = entry.getValue();
			if (Utils.isCollectionNotEmpty(currentOrigins) && currentOrigins.contains(origin)) {
				result.add(entry.getKey());
			}
		}
		return result;
	}

	protected List<CertificateRef> getCertificateRefsByOrigin(CertificateRefOrigin origin) {
		List<CertificateRef> result = new ArrayList<>();
		for (Entry<CertificateRef, List<CertificateRefOrigin>> entry : certificateRefOrigins.entrySet()) {
			List<CertificateRefOrigin> currentOrigins = entry.getValue();
			if (Utils.isCollectionNotEmpty(currentOrigins) && currentOrigins.contains(origin)) {
				result.add(entry.getKey());
			}
		}
		return result;
	}

}
