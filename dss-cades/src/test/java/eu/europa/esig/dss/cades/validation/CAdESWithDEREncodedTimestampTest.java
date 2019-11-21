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
package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DefaultDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * Unit test added to fix : https://esig-dss.atlassian.net/browse/DSS-662
 *
 */
public class CAdESWithDEREncodedTimestampTest {

	@Test
	public void testFile1() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-3.p7m");
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);

		List<String> timestampIdList = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertTrue(Utils.isCollectionEmpty(timestampIdList));
	}

	@Test
	public void testFile2() {
		DSSDocument dssDocument = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-4.p7m");
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		// reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);

		List<String> timestampIdList = diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId());
		assertTrue(Utils.isCollectionEmpty(timestampIdList));
	}

	@Test
	public void testFile3() throws DSSException, CMSException, IOException {
		DSSDocument dssDocument = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-CAdES/DE_CRY/Signature-C-DE_CRY-4.p7m");

		CAdESSignature signature = new CAdESSignature(Utils.toByteArray(dssDocument.openStream()));
		CMSSignedData cmsSignedData = signature.getCmsSignedData();
		assertNotNull(cmsSignedData);
	}

	/**
	 * Test case to prevent some NullPointerExcepitn at CAdESSignature-Class.
	 */
	@Test
	public void testFile4() {
		// TimeStampTokene with not valid encoded RevoicationValues
		// (1.2.840.113549.1.9.16.2.24)
		final String base64TST = "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";
		byte[] doc = Utils.fromBase64(base64TST);
		DSSDocument dssDocument = new InMemoryDocument(doc);
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

}
