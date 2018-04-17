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
import org.bouncycastle.asn1.x509.X509Name;

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
 * Clase para el tratamiento de los certificados reconocidos para ciudadanos de la ACCV, tanto
 * en soporte software como en dispositivo seguro, seg�n las pol�ticas definidas en las URLs: 
 * <a href="http://www.accv.es/pdf-politicas/ACCV-CP-07V4.0-c.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/ACCV-CP-07V4.0-c.pdf</a>,
 * <a href="http://www.accv.es/pdf-politicas/ACCV-CP-07V3.0-c.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/ACCV-CP-07V3.0-c.pdf</a>,
 * <a href="http://www.accv.es/pdf-politicas/ACCV-CP-06V5.0-c.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/ACCV-CP-06V5.0-c.pdf</a> y 
 * <a href="http://www.accv.es/pdf-politicas/ACCV-CP-06V4.0-c.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/ACCV-CP-06V4.0-c.pdf</a>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class CertificadoCiudadano extends CertificadoPersona  {

	/**
	 * Alias del keystore donde se guarda el certificado de firma
	 */
	public static final String ALIAS_KEYSTORE_FIRMA = "FIRMA";

	/**
	 * Alias del keystore donde se guarda el certificado de cifrado
	 */
	public static final String ALIAS_KEYSTORE_CIFRADO = "CIFRADO";

	/**
	 * Base del OID de la pol�tica de certificados de ciudadano en dispositivo seguro
	 */
	public static final String POLICY_IN_PKCS11_DEVICE = "1.3.6.1.4.1.8149.3.6";

	/**
	 * Base del OID de la pol�tica de certificados de ciudadano en dispositivo software
	 */
	public static final String POLICY_IN_SOFTWARE_DEVICE = "1.3.6.1.4.1.8149.3.7";

	/**
	 * Base del OID de la pol�tica de certificados de ciudadano en la nube
	 */
	public static final String POLICY_IN_CLOUD = "1.3.6.1.4.1.8149.3.23";

	/*
	 * Logger de la clas
	 */
	static Logger logger = Logger.getLogger(CertificadoCiudadano.class);
	
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
	public CertificadoCiudadano(X509Certificate certificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoCiudadano(File fileCertificate) throws CertificateCANotFoundException, NormalizeCertificateException, FileNotFoundException {
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
	public CertificadoCiudadano(InputStream isCertificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoCiudadano(byte[] contenidoCertificado) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	 * M�todo que indica si el certificado es v�lido para el cifrado de datos.
	 * 
	 * @return Cierto si el certificado es v�lido para el cifrado de datos
	 */
	public boolean isCipherCertificate () {
		logger.debug("[CertificadoCiudadano.isCipherCertificate]::Entrada");
		return isKeyUsageDataEncipherment() || isKeyUsageKeyEncipherment();
	}
	
	/**
	 * M�todo que indica si el certificado es v�lido para la firma digital.
	 * 
	 * @return Cierto si el certificado es v�lido para la firma digital
	 */
	public boolean isSigningCertificate () {
		logger.debug("[CertificadoCiudadano.isSigningCertificate]::Entrada");
		return isKeyUsageDigitalSignature();
	}
	
	/**
	 * M�todo que devuelve el nombre del titular del certificado
	 * 
	 * @return Nombre del titular del certificado
	 */
	public String getName () {
		return getElementSubject(X509Name.GIVENNAME);
	}
	
	/**
	 * M�todo que devuelve el primer apellido del titular del certificado
	 * 
	 * @return Primer apellido del titular del certificado
	 */
	public String getFirstSurname () {
		
		logger.debug ("[CertificadoCiudadano.getFirstSurname]::Entrada");
		
		String[] nombreCompleto = getNombreCompleto();
		if (nombreCompleto == null) {
			return null;
		}
		
		return nombreCompleto[1].trim();
	}
	
	/**
	 * M�todo que devuelve el segundo apellido del titular del certificado
	 * 
	 * @return Segundo apellido del titular del certificado
	 */
	public String getSecondSurname () {
		
		logger.debug ("[CertificadoCiudadano.getSecondSurname]::Entrada");
		
		String[] nombreCompleto = getNombreCompleto();
		
		//-- El segundo apellido no es obligatorio
		if (nombreCompleto == null || nombreCompleto.length < 3) {
			return "";
		}
		
		return nombreCompleto[2].trim();
	}
	
	/**
	 * M�todo que devuelve los apellidos del titular del certificado
	 * 
	 * @return Apellidos del titular del certificado
	 */
	public String getSurnames () {
		
		logger.debug ("[CertificadoCiudadano.getSurnames]::Entrada");
		
		return getFirstSurname() + " " + getSecondSurname();
	}
	
	/**
	 * M�todo que devuelve el NIF del titular del certificado
	 * 
	 * @return NIF del titular del certificado
	 */
	public String getNIF () {
		return getElementSubject(BCStyle.SERIALNUMBER);
	}
	
	/**
	 * M�todo que devuelve la direcci�n de correo electr�nico del titular del certificado
	 * 
	 * @return E-mail del titular del certificado
	 */
	public String getEmail () {
		
		logger.debug ("[CertificadoCiudadano.getEmail]::Entrada");
		
		List altNames;
		try {
			altNames = getSubjectAlternativeName();
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoCiudadano.getEmail]::No ha sido posible obtener el e-mail del ciudadano", e);
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
		logger.debug ("[CertificadoCiudadano.isInPkcs11Device]::Entrada");
		
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
		logger.debug ("[CertificadoCiudadano.isInSoftwareDevice]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_IN_SOFTWARE_DEVICE)) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * El certificado se encuentra en la nube
	 * 
	 * @return Cierto si el certificado se encuentra en la nube
	 */
	public boolean isInCloud () {
		logger.debug ("[CertificadoCiudadano.isInCloud]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_IN_CLOUD)) {
				return true;
			}
		}
		
		return false;
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
			logger.info ("[CertificadoCiudadano.getCAList]::Alguno de los certificados de las CA no ha podido ser " +
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
			logger.info ("[CertificadoCiudadano.getCAList]::No ha sido posible parsear el fichero de validaci�n XML", e);
			throw new CertificateCANotFoundException ("No ha sido posible parsear el fichero de validaci�n XML", e);
		} catch (ResourceNotLoadedException e) {
			//-- Si no se encuentra pasaremos sin �l, s�lo que no funcionar�n los certificados de test
			logger.info ("[CertificadoCiudadano.getCAList]::No ha sido posible obtener el fichero de validaci�n XML", e);
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
				POLICY_IN_PKCS11_DEVICE, // versi�n en DS
				POLICY_IN_SOFTWARE_DEVICE, // version en SW
				POLICY_IN_CLOUD // version en la nube
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
		
		certificate = ArangiUtil.loadCertificate("certificate/CAGVA");
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
		
		//-- A�adir los certificados de test
		List lCACertificates = new ArrayList ();
		X509Certificate certificate = ArangiUtil.loadCertificate("certificate/TEST_SUBCA_WINDOWS3");
		setTestCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/TEST_ROOT_EJBCA");
		setTestCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/TEST_CATEST");
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

	/*
	 * Obtiene el nombre completo que hay en la extensi�n Subject Alternative Name como
	 * entrada del LDAP. El array tendr� 3 elementos: nombre, apellido 1 y apellido 2
	 */
	private String [] getNombreCompleto () {
		
		String nombreCompleto;
		try {
			nombreCompleto = getSubjectAlternativeNameElement(OID_ID_AT_COMMONNAME);
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoCiudadano.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		if (nombreCompleto == null || nombreCompleto.length() == 0) {
			logger.info ("[CertificadoCiudadano.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		return nombreCompleto.split("\\|");

	}
	
}
