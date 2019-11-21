package eu.europa.esig.dss.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampValidator;

public class TimestampValidatorTest {
	
	@Test
	public void testWithAttached() throws Exception {
		DSSDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");
		DSSDocument timestampedContent = new InMemoryDocument("Test123".getBytes());
		
		TimestampValidator timestampValidator = new TimestampValidator(timestamp, timestampedContent, TimestampType.CONTENT_TIMESTAMP);
		timestampValidator.setCertificateVerifier(new CommonCertificateVerifier());
		
		Reports reports = timestampValidator.validate();
		
		reports.print();

		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getXmlDiagnosticData());
		assertNotNull(reports.getDetailedReportJaxb());
		assertNotNull(reports.getXmlDetailedReport());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getXmlSimpleReport());

		SimpleReportFacade simpleReportFacade = SimpleReportFacade.newFacade();
		String marshalled = simpleReportFacade.marshall(reports.getSimpleReportJaxb(), true);
		assertNotNull(marshalled);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		TimestampWrapper timestampWrapper = timestampList.get(0);
		
		assertTrue(timestampWrapper.isMessageImprintDataFound());
		assertTrue(timestampWrapper.isMessageImprintDataIntact());
		
	}

}
