/**
 * LICENCIA LGPL:
 * 
 * Esta librer�a es Software Libre; Usted puede redistribuirla y/o modificarla
 * bajo los t�rminos de la GNU Lesser General Public License (LGPL) tal y como 
 * ha sido publicada por la Free Software Foundation; o bien la versi�n 2.1 de 
 * la Licencia, o (a su elecci�n) cualquier versi�n posterior.
 * 
 * Esta librer�a se distribuye con la esperanza de que sea �til, pero SIN 
 * NINGUNA GARANT�A; tampoco las impl�citas garant�as de MERCANTILIDAD o 
 * ADECUACI�N A UN PROP�SITO PARTICULAR. Consulte la GNU Lesser General Public 
 * License (LGPL) para m�s detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL) 
 * junto con esta librer�a; si no es as�, escriba a la Free Software Foundation 
 * Inc. 51 Franklin Street, 5� Piso, Boston, MA 02110-1301, USA o consulte
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2011 Agencia de Tecnolog�a y Certificaci�n Electr�nica
 */
package es.accv.arangi.certificate;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.style.BCStyle;

import es.accv.arangi.base.certificate.Certificate;
import es.accv.arangi.base.certificate.validation.CAList;
import es.accv.arangi.base.exception.certificate.CertificateCANotFoundException;
import es.accv.arangi.base.exception.certificate.CertificateFieldException;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.certificate.ValidationXMLException;
import es.accv.arangi.base.util.AlternativeNameElement;
import es.accv.arangi.exception.ResourceNotLoadedException;
import es.accv.arangi.util.ArangiUtil;

/**
 * Clase para el tratamiento de los certificados reconocidos de sello de �rgano de la ACCV, tanto
 * en soporte software como en dispositivo seguro, seg�n las pol�ticas definidas en las URLs: 
 * <a href="http://www.accv.es/pdf-politicas/ACCV-CP-17V1.0-c.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/ACCV-CP-17V1.0-c.pdf</a> y
 * <a href="http://www.accv.es/pdf-politicas/ACCV-CP-16V1.0-c.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/ACCV-CP-16V1.0-c.pdf</a>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class CertificadoSello extends CertificadoACCV {

	/**
	 * Base del OID de la pol�tica de certificados de sello en dispositivo seguro
	 */
	public static final String POLICY_IN_PKCS11_DEVICE = "1.3.6.1.4.1.8149.3.16";

	/**
	 * Base del OID de la pol�tica de certificados de sello en dispositivo software
	 */
	public static final String POLICY_IN_SOFTWARE_DEVICE = "1.3.6.1.4.1.8149.3.17";

	/**
	 * OID base de los campos del SAN para HW
	 */
	private static final String OID_HW_SAN = "2.16.724.1.3.5.6.1";

	/**
	 * OID base de los campos del SAN para SW
	 */
	private static final String OID_SW_SAN = "2.16.724.1.3.5.6.2";

	/*
	 * Logger de la clase
	 */
	static Logger logger = Logger.getLogger(CertificadoSello.class);
	
	/*
	 * Lista de SKI de los certificados de CA de explotaci�n
	 */
	private static HashSet setExplotationCACertificates = new HashSet();
	
	/*
	 * Lista de SKI de los certificados de CA de test
	 */
	private static HashSet setTestCACertificates = new HashSet();
	
	/**
	 * Constructor con un certificado X509Certificate
	 * 
	 * @param certificate Certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 */
	public CertificadoSello(X509Certificate certificate) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(certificate, getCAList());
	}
	
	/**
	 * Constructor con un fichero que contiene un certificado
	 * 
	 * @param fileCertificate Fichero que contiene un certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 * @throws FileNotFoundException El fichero no existe
	 */
	public CertificadoSello(File fileCertificate) throws CertificateCANotFoundException, NormalizeCertificateException, FileNotFoundException {
		super(fileCertificate, getCAList());
	}
	
	/**
	 * Constructor con un fichero que contiene un certificado
	 * 
	 * @param isCertificate Stream de lectura a un certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 */
	public CertificadoSello(InputStream isCertificate) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(isCertificate, getCAList());
	}
	
	/**
	 * Constructor con un fichero que contiene un certificado
	 * 
	 * @param contenidoCertificado Contenido de un certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 */
	public CertificadoSello(byte[] contenidoCertificado) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(contenidoCertificado, getCAList());
	}
	
	//-- M�todos p�blicos
	
	/**
	 * Comprueba si el certificado es de una CA de test
	 * 
	 * @return Cierto si el certificado es de una CA de test
	 */
	public boolean isTestCertificate () {
		logger.debug("[CertificadoCiudadano.isTestCertificate]::Entrada");
		return setTestCACertificates.contains(getIssuerKeyIdentifier());
	}
	
	/**
	 * M�todo que devuelve el nombre descriptivo del sistema autom�tico
	 * 
	 * @return Nombre de la aplicaci�n que representa este certificado
	 */
	public String getName () {
		
		logger.debug ("[CertificadoSello.getName]::Entrada");
		
		return getCommonName();
	}
	
	/**
	 * M�todo que devuelve la denominaci�n (nombre �oficial�) de la Administraci�n, 
	 * organismo o entidad de derecho p�blico suscriptora del certificado
	 * 
	 * @return Nombre de la entidad suscriptora
	 */
	public String getEntityName () {
		
		logger.debug ("[CertificadoSello.getEntityName]::Entrada");
		
		return getElementSubject(BCStyle.O);
	}
	
	/**
	 * M�todo que devuelve el NIF de la Administraci�n, organismo o entidad de derecho 
	 * p�blico suscriptora del certificado
	 * 
	 * @return NIF de la entidad suscriptora
	 */
	public String getEntityNIF () {
		
		logger.debug ("[CertificadoSello.getEntityNIF]::Entrada");
		
		return getElementSubject(BCStyle.SERIALNUMBER);
	}
	
	/**
	 * M�todo que devuelve el NIF del responsable del certificado
	 * 
	 * @return NIF del responsable del certificado
	 */
	public String getPersonInChargeNIF () {
		
		logger.debug ("[CertificadoSello.getPersonInChargeNIF]::Entrada");
		
		try {
			if (isInPkcs11Device()) {
				return getSubjectAlternativeNameElement(OID_HW_SAN + ".4");
			} else {
				return getSubjectAlternativeNameElement(OID_SW_SAN + ".4");
			}
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSello.getPersonInChargeNIF]::No se puede obtener el nombre del representante", e);
			return null;
		}
	}
	
	/**
	 * M�todo que devuelve el nombre del responsable del certificado
	 * 
	 * @return Nombre del responsable del certificado
	 */
	public String getPersonInChargeName () {
		
		logger.debug ("[CertificadoSello.getPersonInChargeName]::Entrada");
		
		try {
			if (isInPkcs11Device()) {
				return getSubjectAlternativeNameElement(OID_HW_SAN + ".6");
			} else {
				return getSubjectAlternativeNameElement(OID_SW_SAN + ".6");
			}
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSello.getPersonInChargeName]::No se puede obtener el nombre del representante", e);
			return null;
		}
	}
	
	/**
	 * M�todo que devuelve el primer apellido del responsable del certificado
	 * 
	 * @return Primer apellido del responsable del certificado
	 */
	public String getPersonInChargeFirstSurname () {
		
		logger.debug ("[CertificadoSello.getPersonInChargeFirstSurname]::Entrada");
		
		try {
			if (isInPkcs11Device()) {
				return getSubjectAlternativeNameElement(OID_HW_SAN + ".7");
			} else {
				return getSubjectAlternativeNameElement(OID_SW_SAN + ".7");
			}
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSello.getPersonInChargeFirstSurname]::No se puede obtener el primer apellido del representante", e);
			return null;
		}
	}
	
	/**
	 * M�todo que devuelve el segundo apellido del responsable del certificado
	 * 
	 * @return Segundo apellido del responsable del certificado
	 */
	public String getPersonInChargeSecondSurname () {
		
		logger.debug ("[CertificadoSello.getPersonInChargeSecondSurname]::Entrada");
		
		try {
			if (isInPkcs11Device()) {
				return getSubjectAlternativeNameElement(OID_HW_SAN + ".8");
			} else {
				return getSubjectAlternativeNameElement(OID_SW_SAN + ".8");
			}
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSello.getPersonInChargeSecondSurname]::No se puede obtener el segundo apellido del representante", e);
			return null;
		}
	}
	
	/**
	 * M�todo que devuelve los apellidos del responsable del certificado
	 * 
	 * @return Apellidos del titular del certificado
	 */
	public String getPersonInChargeSurnames () {
		
		logger.debug ("[CertificadoSello.getPersonInChargeSurnames]::Entrada");
		
		return getPersonInChargeFirstSurname() + " " + getPersonInChargeSecondSurname();
	}
	
	/**
	 * M�todo que devuelve la direcci�n de correo electr�nico de la entidad
	 * responsable de la aplicaci�n
	 * 
	 * @return E-mail de la entidad responsable
	 */
	public String getEmail () {
		
		logger.debug ("[CertificadoSello.getEmail]::Entrada");
		
		List altNames;
		try {
			altNames = getSubjectAlternativeName();
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSello.getEmail]::No ha sido posible obtener el e-mail de la entidad", e);
			return null;
		}
	
		//-- Es el primer elemento del nombre alternativo
		return (String) ((AlternativeNameElement) altNames.get(0)).getValue();
	}
	
	/**
	 * El certificado se encuentra en un dispositivo PKCS#11
	 * 
	 * @return Cierto si el certificado se encuentra en un dispositivo PKCS#11
	 */
	public boolean isInPkcs11Device () {
		logger.debug ("[CertificadoSello.isInPkcs11Device]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_IN_PKCS11_DEVICE)) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * El certificado se encuentra en un dispositivo software (PKCS#12)
	 * 
	 * @return Cierto si el certificado se encuentra en un dispositivo software (PKCS#12)
	 */
	public boolean isInSoftwareDevice () {
		logger.debug ("[CertificadoSello.isInSoftwareDevice]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_IN_SOFTWARE_DEVICE)) {
				return true;
			}
		}
		
		return false;
	}
	
	@Override
	public boolean isCipherCertificate() {
		return false;
	}

	@Override
	public boolean isSigningCertificate() {
		return true;
	}
	
	/**
	 * Obtiene la lista de certificados de CA y ra�z que conforman las posibles cadenas
	 * de confianza de los certificados de esta clase. 
	 */
	public static CAList getCAList() throws CertificateCANotFoundException {
		
		//-- A�adir los certificados de test y de explotaci�n
		List lCACertificates = getCAListExlotation();
		lCACertificates.addAll(getCAListTest());
		
		CAList caList;
		try {
			caList = new CAList (lCACertificates);
		} catch (NormalizeCertificateException e) {
			//-- Si alg�n certificado no puede ser normalizado lo pasamos como que no
			//-- se ha podido cargar
			logger.info ("[CertificadoSello.getCAList]::Alguno de los certificados de las CA no ha podido ser " +
					"normalizado a lo esperado por el proveedor criptogr�fico de Arangi", e);
			throw new CertificateCANotFoundException ("Alguno de los certificados de las CA no ha podido ser " +
					"normalizado a lo esperado por el proveedor criptogr�fico de Arangi", e);
		};
		
		//-- A�adir el fichero para validar los certificados de test
		try {
			caList.setValidationXML(ArangiUtil.loadFile("file/validation_data_accv_test.xml"));
		} catch (ValidationXMLException e) {
			//-- Si no se ha podido parsear el fichero de validaci�n lo pasamos como que
			//-- no se han podido cargar los certificados de las CA
			logger.info ("[CertificadoSello.getCAList]::No ha sido posible parsear el fichero de validaci�n XML", e);
			throw new CertificateCANotFoundException ("No ha sido posible parsear el fichero de validaci�n XML", e);
		} catch (ResourceNotLoadedException e) {
			//-- Si no se encuentra pasaremos sin �l, s�lo que no funcionar�n los certificados de test
			logger.info ("[CertificadoSello.getCAList]::No ha sido posible obtener el fichero de validaci�n XML", e);
		}
		
		return caList;
	}

	//-- M�todos protected
	
	/**
	 * Usado por la clase CertificateFactory para dar de alta la clase en la lista
	 * de tipos de certificados.
	 * 
	 * @return OID base de la pol�tica
	 */
	protected static String [] getBasePolicies () {
		return new String[] {
				POLICY_IN_PKCS11_DEVICE,  	// dispositivo seguro
				POLICY_IN_SOFTWARE_DEVICE	// soporte SW
		};
	}

	//-- M�todos privados
	
	/*
	 * Obtiene la lista de certificados de CA y ra�z que conforman las posibles cadenas
	 * de confianza de los certificados de explotaci�n de esta clase. 
	 */
	private static List getCAListExlotation() throws CertificateCANotFoundException {
		
		//-- A�adir los certificados de explotaci�n
		List lCACertificates = new ArrayList ();
		X509Certificate certificate = ArangiUtil.loadCertificate("certificate/ACCV-CA2");
		setExplotationCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ROOT_CA");
		setExplotationCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		//-- Nueva CA
		certificate = ArangiUtil.loadCertificate("certificate/ACCV-CA120-SHA256");
		setExplotationCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ACCVRAIZ1");
		setExplotationCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		return lCACertificates;
	}
	
	/*
	 * Obtiene la lista de certificados de CA y ra�z que conforman las posibles cadenas
	 * de confianza de los certificados de test de esta clase. 
	 */
	private static List getCAListTest() throws CertificateCANotFoundException {
		
		//-- A�adir los certificados de test y de explotaci�n
		List lCACertificates = new ArrayList ();
		X509Certificate certificate = ArangiUtil.loadCertificate("certificate/TEST_SUBCA_WINDOWS3");
		setTestCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/TEST_ROOT_EJBCA");
		setTestCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ACCVCATEST120");
		setTestCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ROOTEJB4TEST");
		setTestCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		return lCACertificates;
	}

}
