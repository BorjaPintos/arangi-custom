/*
 * 17-abr-2018 - File: - BBDDCerts.java
 * Author: Borja Pintos Castro - borjapintoscastro@gmail.com
 */
package es.accv.arangi.util;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import es.accv.arangi.base.exception.certificate.CertificateCANotFoundException;

/**
 * The Class BBDDCerts.
 */
public class BBDDCerts {

	/** The logger. */
	static Logger logger = Logger.getLogger(BBDDCerts.class);

	/** The instance. */
	private static BBDDCerts instance;

	/** The certificates CA. */
	private List<X509Certificate> certificatesCA = new ArrayList<X509Certificate>();

	/**
	 * Instantiates a new BBDD certs.
	 */
	private BBDDCerts() {
		logger.debug("[BBDDCerts.newInstsance]::Entrada");
		try {

			addCaBaltimore();

			addCaAntigua();

			addCaNueva();
			
			addCaDNIe();

		} catch (CertificateCANotFoundException e) {
			logger.info("[BBDDCerts.newInstsance]::No se encuentra alguno de los certificados de la ACCV", e);
		}
	}

	/**
	 * Gets the single instance of BBDDCerts.
	 *
	 * @return single instance of BBDDCerts
	 */
	public static BBDDCerts getInstance() {
		if (instance == null) {
			instance = new BBDDCerts();
		}
		return instance;
	}

	/**
	 * Gets the certificates CA.
	 *
	 * @return the certificates CA
	 */
	public List<X509Certificate> getCertificatesCA() {
		return certificatesCA;
	}

	/**
	 * Put CA.
	 *
	 * @param name the name
	 * @param folderPath the folder path
	 * @throws CertificateCANotFoundException the certificate CA not found exception
	 */
	public void putCA(String name, String folderPath) throws CertificateCANotFoundException {
		certificatesCA.add(ArangiUtil.loadCertificate(name, folderPath));
	}

	/**
	 * Adds the ca baltimore.
	 *
	 * @throws CertificateCANotFoundException the certificate CA not found exception
	 */
	private void addCaBaltimore() throws CertificateCANotFoundException {
		// -- CA Baltimore
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/CAGVA"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/TEST_CATEST"));
	}

	/**
	 * Adds the ca antigua.
	 *
	 * @throws CertificateCANotFoundException the certificate CA not found exception
	 */
	private void addCaAntigua() throws CertificateCANotFoundException {
		// -- CA Antigua
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ROOT_CA"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCV-CA1"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCV-CA2"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/TEST_ROOT_EJBCA"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/TEST_SUBCA_WINDOWS3"));
	}

	/**
	 * Adds the ca nueva.
	 *
	 * @throws CertificateCANotFoundException the certificate CA not found exception
	 */
	private void addCaNueva() throws CertificateCANotFoundException {
		// -- CA Nueva
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCVRAIZ1"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCV-CA110-SHA1"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCV-CA110-SHA256"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCV-CA120-SHA1"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCV-CA120-SHA256"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCV-CA130-SHA1"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCV-CA130-SHA256"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ROOTEJB4TEST"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCVCATEST110"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCVCATEST120"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACCVCATEST130"));
	}

	/**
	 * Adds the ca DN ie.
	 *
	 * @throws CertificateCANotFoundException the certificate CA not found exception
	 */
	private void addCaDNIe() throws CertificateCANotFoundException {
		// -- DNIe
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACRAIZ-SHA2"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACDNIE001-SHA2"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACDNIE002-SHA2"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACDNIE003-SHA2"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACDNIE004-SHA2"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACDNIE005-SHA2"));
		certificatesCA.add(ArangiUtil.loadCertificate("certificate/ACDNIE006-SHA2"));
	}
	
}
