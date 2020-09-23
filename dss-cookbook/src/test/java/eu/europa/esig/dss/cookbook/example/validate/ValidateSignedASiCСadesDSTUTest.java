/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustProperties;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.sync.AcceptAllStrategy;
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * How to validate a XAdES-BASELINE-B signature.
 */
public class ValidateSignedASiCСadesDSTUTest {

	@Test
	public void validateXAdESBaselineB() throws Exception {

		// See Trusted Lists loading
		// CertificateSource keystoreCertSource = new CertificateToken.
		// CertificateSource adjunctCertSource = new KeyStoreCertificateSource(new File("src/test/resources/self-signed-tsa.p12"), "PKCS12", "ks-password");

		// tag::demo[]

		// First, we need a Certificate verifier
		CertificateVerifier cv = new CommonCertificateVerifier();

		TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
		CommonTrustedCertificateSource cs = new CommonTrustedCertificateSource();
		//cs.addCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CertificateSN1015139.cer")));

		cs.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
		/*cs.addCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CA-ACSKInformjust-080415.cer")));
		cs.addCertificate(DSSUtils.loadCertificate(new File("src/test/resources/czo-dstu.cer")));
		//cs.addCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CZO-ROOT-2017.cer")));
		cs.addCertificate(DSSUtils.loadCertificate(new File("src/test/resources/CZOROOT.cer")));
		cs.addCertificate(DSSUtils.loadCertificate(new File("src/test/resources/dia.cer")));*/

		/*TLValidationJob job = new TLValidationJob();

		FileCacheDataLoader onlineloader = new FileCacheDataLoader (new CommonsDataLoader());
		onlineloader.remove("https://javatask-dev-bucket.s3-eu-west-1.amazonaws.com/TL-UA-DSTU.xml");

		job.setOnlineDataLoader(onlineloader);
		//job.setTrustedListCertificateSource(trustedCertificateSource());
		job.setSynchronizationStrategy(new AcceptAllStrategy());
		ExpirationAndSignatureCheckStrategy expirationAndSignatureCheckStrategy = new ExpirationAndSignatureCheckStrategy();
		expirationAndSignatureCheckStrategy.setAcceptInvalidTrustedList(true);
		//expirationAndSignatureCheckStrategy.;
		job.setSynchronizationStrategy(expirationAndSignatureCheckStrategy);


		TLSource uadstu = new TLSource();
		uadstu.setUrl("https://javatask-dev-bucket.s3-eu-west-1.amazonaws.com/TL-UA-DSTU.xml");
		uadstu.setCertificateSource(new );
		job.setTrustedListSources(uadstu);

		job.setTrustedListCertificateSource(trustedListsCertificateSource);
		job.onlineRefresh();*/
		cv.setTrustedCertSources(cs);


		// DSS requires the country code, the URL and allowed signing certificat
		// We can inject several sources. eg: OCSP, CRL, AIA, trusted lists

		// Capability to download resources from AIA
		cv.setDataLoader(new CommonsDataLoader());

		// Capability to request OCSP Responders
		cv.setOcspSource(new OnlineOCSPSource());

		// Capability to download CRL
		cv.setCrlSource(new OnlineCRLSource());
		
		// Create an instance of a trusted certificate source
		//CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
		// import the keystore as trusted
		// trustedCertSource.addCertificate(new CertificateToken());

		// Add trust anchors (trusted list, keystore,...) to a list of trusted certificate sources
		// Hint : use method {@code CertificateVerifier.setTrustedCertSources(certSources)} in order to overwrite the existing list
		//cv.addTrustedCertSources(trustedCertSource);
		//cv.addTrustedCertSources(trustedListsCertificateSource);
		//cv.setTrustedCertSources(cs);


		// Additionally add missing certificates to a list of adjunct certificate sources
		//cv.addAdjunctCertSources(adjunctCertSource);

		// Here is the document to be validated (any kind of signature file)
		DSSDocument document = new FileDocument(new File("src/test/resources/contract.zip"));

		// We create an instance of DocumentValidator
		// It will automatically select the supported validator from the classpath
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);

		// We add the certificate verifier (which allows to verify and trust certificates)
		documentValidator.setCertificateVerifier(cv);

		// Here, everything is ready. We can execute the validation (for the example, we use the default and embedded
		// validation policy)
		Reports reports = documentValidator.validateDocument();

		// We have 3 reports
		// The diagnostic data which contains all used and static data
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		// The detailed report which is the result of the process of the diagnostic data and the validation policy
		DetailedReport detailedReport = reports.getDetailedReport();

		// The simple report is a summary of the detailed report (more user-friendly)
		SimpleReport simpleReport = reports.getSimpleReport();

		Indication indication = simpleReport.getIndication(simpleReport.getFirstSignatureId());


		// end::demo[]

		System.out.println(indication.getUri());


		assertNotNull(reports);
		assertNotNull(diagnosticData);
		assertNotNull(detailedReport);
		assertNotNull(simpleReport);

	}

}
