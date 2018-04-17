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
 * Clase para el tratamiento de los certificados reconocidos de seud�nimo de la ACCV, 
 * seg�n la pol�tica definida en la URL: 
 * <a href="http://www.accv.es/pdf-politicas/ACCV-CP-13V2.0-c.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/ACCV-CP-13V2.0-c.pdf</a>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class CertificadoSeudonimo extends CertificadoACCV implements CertificadoEmpleado {

	/*
	 * Logger de la clas
	 */
	static Logger logger = Logger.getLogger(CertificadoSeudonimo.class);
	
	/**
	 * Base del OID de la pol�tica de certificados de seud�nimo en dispositivo seguro
	 */
	public static final String POLICY_IN_PKCS11_DEVICE = "1.3.6.1.4.1.8149.3.21";

	/**
	 * Base del OID de la pol�tica de certificados de seud�nimo en dispositivo software
	 */
	public static final String POLICY_IN_SOFTWARE_DEVICE = "1.3.6.1.4.1.8149.3.27";

	/**
	 * Base del OID de la pol�tica de certificados de seud�nimo en la nube
	 */
	public static final String POLICY_IN_CLOUD = "1.3.6.1.4.1.8149.3.28";

	/**
	 * OID del campo con el cargo del empleado p�blico: versi�n 1 de la pol�tica
	 */
	public static final String OID_CARGO_VERSION_1 = "1.3.6.1.4.1.8149.4.3.11"; 
	
	/**
	 * OID del campo con el seud�nimo: versi�n 1 de la pol�tica
	 */
	public static final String OID_SEUDONIMO_VERSION_1 = "1.3.6.1.4.1.8149.4.3.4"; 
	
	/**
	 * OID del campo con el CIF del organismo: versi�n 1 de la pol�tica
	 */
	public static final String OID_CIF_ORGANISMO_VERSION_1 = "1.3.6.1.4.1.8149.4.3.3"; 
	
	/**
	 * OID del campo con el nombre del organismo: versi�n 1 de la pol�tica
	 */
	public static final String OID_NOMBRE_ORGANISMO_VERSION_1	= "1.3.6.1.4.1.8149.4.3.2"; 
	
	/**
	 * OID del campo con la unidad donde trabaja el propietario del seud�nimo: versi�n 1 de la pol�tica
	 */
	public static final String OID_UNIDAD_VERSION_1	= "1.3.6.1.4.1.8149.4.3.10"; 
	
	/**
	 * OID del campo con el cargo del empleado p�blico: versi�n 2 de la pol�tica
	 */
	public static final String OID_CARGO_VERSION_2 = "2.16.724.1.3.5.4.2.11"; 
	
	/**
	 * OID del campo con el seud�nimo: versi�n 2 de la pol�tica
	 */
	public static final String OID_SEUDONIMO_VERSION_2 = "2.16.724.1.3.5.4.2.12"; 
	
	/**
	 * OID del campo con el CIF del organismo: versi�n 2 de la pol�tica
	 */
	public static final String OID_CIF_ORGANISMO_VERSION_2 = "2.16.724.1.3.5.4.2.3"; 
	
	/**
	 * OID del campo con el nombre del organismo: versi�n 2 de la pol�tica
	 */
	public static final String OID_NOMBRE_ORGANISMO_VERSION_2	= "2.16.724.1.3.5.4.2.2"; 
	
	/**
	 * OID del campo con la unidad donde trabaja el propietario del seud�nimo: versi�n 2 de la pol�tica
	 */
	public static final String OID_UNIDAD_VERSION_2	= "2.16.724.1.3.5.4.2.10"; 
	
	/**
	 * Alias del keystore donde se guarda el certificado
	 */
	public static final String ALIAS_PKCS11 = "SEUD";

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
	public CertificadoSeudonimo(X509Certificate certificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoSeudonimo(File fileCertificate) throws CertificateCANotFoundException, NormalizeCertificateException, FileNotFoundException {
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
	public CertificadoSeudonimo(InputStream isCertificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoSeudonimo(byte[] contenidoCertificado) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(contenidoCertificado, getCAList());
	}
	
	//-- M�todos p�blicos
	
	/**
	 * Comprueba si el certificado es de una CA de test
	 * 
	 * @return Cierto si el certificado es de una CA de test
	 */
	public boolean isTestCertificate () {
		logger.debug("[CertificadoSeudonimo.isTestCertificate]::Entrada");
		return setTestCACertificates.contains(getIssuerKeyIdentifier());
	}
	
	/**
	 * M�todo que devuelve el seud�nimo del titular del certificado
	 * 
	 * @return Seud�nimo del titular del certificado
	 */
	public String getPseudonym () {
		
		logger.debug ("[CertificadoSeudonimo.getPseudonym]::Entrada");
		
		String result = null;
		try {
			result = getSubjectAlternativeNameElement(OID_SEUDONIMO_VERSION_1);
			if (result != null) {
				return result;
			} else {
				return getSubjectAlternativeNameElement(OID_SEUDONIMO_VERSION_2);
			}
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSeudonimo.getPosition]::No se puede obtener el seud�nimo", e);
			return null;
		}
	}
	
	/**
	 * M�todo que obtiene el valor diferenciador para este tipo
	 * de certificados
	 */
	public String getNRPPseudonym() {
		return getPseudonym();
	}
	
	/**
	 * M�todo que devuelve la direcci�n de correo electr�nico del titular del certificado
	 * 
	 * @return E-mail del titular del certificado
	 */
	public String getEmail () {
		
		logger.debug ("[CertificadoSeudonimo.getEmail]::Entrada");
		
		List altNames;
		try {
			altNames = getSubjectAlternativeName();
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSeudonimo.getEmail]::No ha sido posible obtener el e-mail", e);
			return null;
		}
	
		//-- Es el primer elemento del nombre alternativo
		return (String) ((AlternativeNameElement) altNames.get(0)).getValue();
	}
	
	/**
	 * M�todo que obtiene el cargo del Empleado P�blico.
	 * 
	 * @return Cargo del Empleado P�blico
	 */
	public String getPosition() {
		
		logger.debug ("[CertificadoSeudonimo.getPosition]::Entrada");
		
		String result = null;
		try {
			result = getSubjectAlternativeNameElement(OID_CARGO_VERSION_1);
			if (result != null) {
				return result;
			} else {
				return getSubjectAlternativeNameElement(OID_CARGO_VERSION_2);
			}
		} catch (CertificateFieldException e) {
				logger.info ("[CertificadoSeudonimo.getPosition]::No se puede obtener el cargo", e);
				return null;
		}
	}
	
	/**
	 * M�todo que obtiene el CIF de la entidad suscriptora del certificado.
	 * 
	 * @return CIF de la entidad suscriptora del certificado
	 */
	public String getEntityCIF() {
		
		logger.debug ("[CertificadoSeudonimo.getCIFEntidad]::Entrada");
		
		String result = null;
		try {
			result = getSubjectAlternativeNameElement(OID_CIF_ORGANISMO_VERSION_1);
			if (result != null) {
				return result;
			} else {
				return getSubjectAlternativeNameElement(OID_CIF_ORGANISMO_VERSION_2);
			}
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSeudonimo.getEntityCIF]::No se puede obtener el nombre de la entidad suscriptora", e);
			return null;
		}
	}
	
	/**
	 * M�todo que obtiene el nombre de la entidad suscriptora del certificado.
	 * 
	 * @return Nombre de la entidad suscriptora del certificado
	 */
	public String getEntityName() {
		
		logger.debug ("[CertificadoSeudonimo.getEntityName]::Entrada");
		
		String result = null;
		try {
			result = getSubjectAlternativeNameElement(OID_NOMBRE_ORGANISMO_VERSION_1);
			if (result != null) {
				return result;
			} else {
				return getSubjectAlternativeNameElement(OID_NOMBRE_ORGANISMO_VERSION_2);
			}
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSeudonimo.getEntityName]::No se puede obtener el nombre de la entidad suscriptora", e);
			return null;
		}
	}
	
	/**
	 * Devuelve la Unidad, dentro de la Administraci�n, en la que est� incluida el suscriptor
	 * del certificado.
	 * 
	 * @return Organization Unit del titular del certificado.
	 */
	public String getOrganizationalUnit() {
		
		logger.debug ("[CertificadoSeudonimo.getOrganizationalUnit]::Entrada");

		String result = null;
		try {
			result = getSubjectAlternativeNameElement(OID_UNIDAD_VERSION_1);
			if (result != null) {
				return result;
			} else {
				return getSubjectAlternativeNameElement(OID_UNIDAD_VERSION_2);
			}
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoSeudonimo.getOrganizationalUnit]::No se puede obtener la unidad", e);
			return null;
		}
	}
	
	/**
	 * El certificado se encuentra en un dispositivo PKCS#11
	 * 
	 * @return Cierto si el certificado se encuentra en un dispositivo PKCS#11
	 */
	public boolean isInPkcs11Device () {
		logger.debug ("[CertificadoSeudonimo.isInPkcs11Device]::Entrada");
		
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
		logger.debug ("[CertificadoSeudonimo.isInSoftwareDevice]::Entrada");
		
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
		logger.debug ("[CertificadoSeudonimo.isInCloud]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_IN_CLOUD)) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * M�todo que indica si el certificado es v�lido para el cifrado de datos: NO
	 * 
	 * @return Cierto si el certificado es v�lido para el cifrado de datos
	 */
	public boolean isCipherCertificate() {
		return false;
	}

	/**
	 * M�todo que indica si el certificado es v�lido para la firma digital:SI
	 * 
	 * @return Cierto si el certificado es v�lido para la firma digital
	 */
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
			logger.info ("[CertificadoSeudonimo.getCAList]::Alguno de los certificados de las CA no ha podido ser " +
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
			logger.info ("[CertificadoSeudonimo.getCAList]::No ha sido posible parsear el fichero de validaci�n XML", e);
			throw new CertificateCANotFoundException ("No ha sido posible parsear el fichero de validaci�n XML", e);
		} catch (ResourceNotLoadedException e) {
			//-- Si no se encuentra pasaremos sin �l, s�lo que no funcionar�n los certificados de test
			logger.info ("[CertificadoSeudonimo.getCAList]::No ha sido posible obtener el fichero de validaci�n XML", e);
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
	protected static String[] getBasePolicies () {
		return new String[] { 
				POLICY_IN_PKCS11_DEVICE, // certificados en tarjeta
				POLICY_IN_SOFTWARE_DEVICE, // certificados en software
				POLICY_IN_CLOUD // certificados en la nube 
		};
	}

	//-- M�todos privados
	
	/*
	 * Obtiene la lista de certificados de CA y ra�z que conforman las posibles cadenas
	 * de confianza de los certificados de explotaci�n de esta clase. 
	 */
	private static List getCAListExlotation() throws CertificateCANotFoundException {
		
		//-- Nueva CA
		List lCACertificates = new ArrayList ();
		X509Certificate certificate = ArangiUtil.loadCertificate("certificate/ACCV-CA130-SHA256");
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
		
		List lCACertificates = new ArrayList ();
		X509Certificate certificate = ArangiUtil.loadCertificate("certificate/ACCVCATEST130");
		setTestCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ROOTEJB4TEST");
		setTestCACertificates.add(Certificate.getSubjectKeyIdentifier(certificate));
		lCACertificates.add(certificate);
		
		return lCACertificates;
	}


}
