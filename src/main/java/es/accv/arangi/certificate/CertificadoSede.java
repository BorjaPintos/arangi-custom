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
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
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
 * Clase para el tratamiento de los certificados reconocidos de sede electr�nica de la ACCV, tanto
 * en soporte software como en dispositivo seguro, seg�n las pol�ticas definidas en las URLs: 
 * <a href="http://www.accv.es/pdf-politicas/ACCV-CP-15V1.0-c.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/ACCV-CP-15V1.0-c.pdf</a> y
 * <a href="http://www.accv.es/pdf-politicas/ACCV-CP-14V1.0-c.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/ACCV-CP-14V1.0-c.pdf</a>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class CertificadoSede extends CertificadoACCV {

	/**
	 * Base del OID de la pol�tica de certificados de sede en dispositivo seguro
	 */
	public static final String POLICY_IN_PKCS11_DEVICE = "1.3.6.1.4.1.8149.3.14";

	/**
	 * Base del OID de la pol�tica de certificados de sede en dispositivo software
	 */
	public static final String POLICY_IN_SOFTWARE_DEVICE = "1.3.6.1.4.1.8149.3.15";

	/*
	 * Logger de la clase
	 */
	static Logger logger = Logger.getLogger(CertificadoSede.class);
	
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
	public CertificadoSede(X509Certificate certificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoSede(File fileCertificate) throws CertificateCANotFoundException, NormalizeCertificateException, FileNotFoundException {
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
	public CertificadoSede(InputStream isCertificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoSede(byte[] contenidoCertificado) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(contenidoCertificado, getCAList());
	}
	
	//-- M�todos p�blicos
	
	/**
	 * Comprueba si el certificado es de una CA de test
	 * 
	 * @return Cierto si el certificado es de una CA de test
	 */
	public boolean isTestCertificate () {
		logger.debug("[CertificadoSede.isTestCertificate]::Entrada");
		return setTestCACertificates.contains(getIssuerKeyIdentifier());
	}
	
	/**
	 * M�todo que devuelve la denominaci�n de nombre de dominio (DNS o IP) donde 
	 * residir� el certificado.
	 * 
	 * @return Nombre de de dominio (DNS o IP) donde residir� el certificado
	 */
	public String getName () {
		
		logger.debug ("[CertificadoSede.getName]::Entrada");
		
		return getCommonName();
	}
	
	/**
	 * M�todo que devuelve el valor del DNS1 (coincidir� con lo devuelto por
	 * el m�todo getName).
	 * 
	 * @return DNS1
	 */
	public String getDNS1 () {
		
		logger.debug ("[CertificadoSede.getDNS1]::Entrada");
		
		try {
			List<AlternativeNameElement> lista = getSubjectAlternativeNameElements(GeneralName.dNSName);
			if (lista.isEmpty()) {
				logger.debug ("[CertificadoSede.getDNS1]::No existe DNS");
				return null;
			}
			
			return lista.get(0).getValue().toString();
			
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSede.getDNS1]::No se puede obtener la DNS", e);
			return null;
		}
	}
	
	/**
	 * M�todo que devuelve el valor del DNS2.
	 * 
	 * @return DNS2
	 */
	public String getDNS2 () {
		
		logger.debug ("[CertificadoSede.getDNS2]::Entrada");
		
		try {
			List<AlternativeNameElement> lista = getSubjectAlternativeNameElements(GeneralName.dNSName);
			if (lista.size() < 2) {
				logger.debug ("[CertificadoSede.getDNS2]::No existe DNS");
				return null;
			}
			
			return lista.get(1).getValue().toString();
			
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSede.getDNS2]::No se puede obtener la DNS", e);
			return null;
		}
	}
	
	/**
	 * M�todo que devuelve el valor del DNS3.
	 * 
	 * @return DNS3
	 */
	public String getDNS3 () {
		
		logger.debug ("[CertificadoSede.getDNS3]::Entrada");
		
		try {
			List<AlternativeNameElement> lista = getSubjectAlternativeNameElements(GeneralName.dNSName);
			if (lista.size() < 3) {
				logger.debug ("[CertificadoSede.getDNS3]::No existe DNS");
				return null;
			}
			
			return lista.get(2).getValue().toString();
			
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSede.getDNS3]::No se puede obtener la DNS", e);
			return null;
		}
	}
	
	/**
	 * M�todo que devuelve el nombre descriptivo de la sede
	 * 
	 * @return Nombre de la entidad suscriptora
	 */
	public String getDescriptiveName () {
		
		logger.debug ("[CertificadoSede.getDescriptiveName]::Entrada");
		
		String[] valores = getElementsSubject(X509Name.OU);
		for(String valor : valores) {
			if (!valor.equalsIgnoreCase("SEDE ELECTRONICA")) {
				return valor;
			}
		}
		
		return "SEDE ELECTRONICA";
	}
	
	/**
	 * M�todo que devuelve la denominaci�n (nombre �oficial�) de la Administraci�n, 
	 * organismo o entidad de derecho p�blico suscriptora del certificado, a la que se
	 * encuentra vinculada la sede
	 * 
	 * @return Nombre de la entidad suscriptora
	 */
	public String getEntityName () {
		
		logger.debug ("[CertificadoSede.getEntityName]::Entrada");
		
		return getElementSubject(X509Name.O);
	}
	
	/**
	 * M�todo que devuelve el NIF de la Administraci�n, organismo o entidad de derecho 
	 * p�blico suscriptora del certificado, a la que se encuentra vinculada la sede.
	 * 
	 * @return NIF de la entidad suscriptora
	 */
	public String getEntityNIF () {
		
		logger.debug ("[CertificadoSede.getEntityNIF]::Entrada");
		
		return getElementSubject(X509Name.SERIALNUMBER);
	}
	
	/**
	 * M�todo que obtiene el CIF de la entidad codificado seg�n el ETSI
	 * (s�lo para certificados cualificados de sello de entidad).
	 * 
	 * @return CIF de la entidad seg�n el ETSI
	 */
	public String getEntityNIFETSI() {
		
		logger.debug ("[CertificadoSede.getEntityNIFETSI]::Entrada");
		
		return getElementSubject(new ASN1ObjectIdentifier("2.5.4.97"));
	}
	
	/**
	 * M�todo que obtiene el campo Jurisdiction Country
	 * 
	 * @return Campo Jurisdiction Country
	 */
	public String getJurisdictionCountry() {
		
		logger.debug ("[CertificadoSede.getJurisdictionCountry]::Entrada");
		
		return getElementSubject(new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3"));
	}
	
	/**
	 * M�todo que obtiene el campo Business Category
	 * 
	 * @return Campo  Business Category
	 */
	public String getBusinessCategory() {
		
		logger.debug ("[CertificadoSede.getBusinessCategory]::Entrada");
		
		return getElementSubject(new ASN1ObjectIdentifier("2.5.4.15"));
	}
	
	/**
	 * Devuelve un texto con el nombre del municipio y la provincia donde
	 * se halla ubicado. Si el certificado no dispone de esa informaci�n
	 * devolver� null.
	 * 
	 * @return Localidad
	 */
	public String getLocality () {
		logger.debug ("[CertificadoSede.getLocality]::Entrada");
		
		String municipio = getElementSubject(X509Name.L);
		if (municipio != null) {
			String provincia = getElementSubject(X509Name.ST);
			if (provincia != null) {
				municipio += " (" + provincia + ")";
			}
			return municipio;
		}
		
		return null;
	}
	
	/**
	 * M�todo que devuelve la direcci�n de correo electr�nico de la entidad
	 * responsable de la aplicaci�n
	 * 
	 * @return E-mail de la entidad responsable
	 */
	public String getEmail () {
		
		logger.debug ("[CertificadoSede.getEmail]::Entrada");
		
		List altNames;
		try {
			altNames = getSubjectAlternativeName();
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSede.getEmail]::No ha sido posible obtener el e-mail de la entidad", e);
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
		logger.debug ("[CertificadoSede.isInPkcs11Device]::Entrada");
		
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
		logger.debug ("[CertificadoSede.isInSoftwareDevice]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_IN_SOFTWARE_DEVICE)) {
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
			logger.info ("[CertificadoSede.getCAList]::Alguno de los certificados de las CA no ha podido ser " +
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
			logger.info ("[CertificadoSede.getCAList]::No ha sido posible parsear el fichero de validaci�n XML", e);
			throw new CertificateCANotFoundException ("No ha sido posible parsear el fichero de validaci�n XML", e);
		} catch (ResourceNotLoadedException e) {
			//-- Si no se encuentra pasaremos sin �l, s�lo que no funcionar�n los certificados de test
			logger.info ("[CertificadoSede.getCAList]::No ha sido posible obtener el fichero de validaci�n XML", e);
		}
		
		return caList;
	}

	@Override
	public boolean isCipherCertificate() {
		return false;
	}

	@Override
	public boolean isSigningCertificate() {
		return true;
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

	/*
	 * Obtiene el nombre completo que hay en la extensi�n Subject Alternative Name como
	 * entrada del LDAP. El array tendr� 3 elementos: nombre, apellido 1 y apellido 2
	 */
	private String [] getNombreCompleto () {
		
		String nombreCompleto;
		try {
			nombreCompleto = getSubjectAlternativeNameElement(OID_ID_AT_COMMONNAME);
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSede.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		if (nombreCompleto == null || nombreCompleto.length() == 0) {
			logger.info ("[CertificadoSede.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		return nombreCompleto.split("\\|");

	}

}
