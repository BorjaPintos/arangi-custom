/**
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirla y/o modificarla
 * bajo los términos de la GNU Lesser General Public License (LGPL) tal y como 
 * ha sido publicada por la Free Software Foundation; o bien la versión 2.1 de 
 * la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN 
 * NINGUNA GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o 
 * ADECUACIÓN A UN PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public 
 * License (LGPL) para más detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL) 
 * junto con esta librería; si no es así, escriba a la Free Software Foundation 
 * Inc. 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA o consulte
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2011 Agencia de Tecnología y Certificación Electrónica
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
 * Clase para el tratamiento de los certificados reconocidos de pertenencia a empresa de la ACCV, 
 * según la política definida en la URL: 
 * <a href="http://www.accv.es/pdf-politicas/ACCV-CP-20V1.0.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/ACCV-CP-20V1.0.pdf</a>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class CertificadoPertenenciaEmpresa extends CertificadoPersona implements CertificadoEmpleado {

	/*
	 * Logger de la clase
	 */
	static Logger logger = Logger.getLogger(CertificadoPertenenciaEmpresa.class);
	
	/**
	 * Base del OID de la política de certificados de pe en dispositivo seguro
	 */
	public static final String POLICY_IN_PKCS11_DEVICE = "1.3.6.1.4.1.8149.3.20";

	/**
	 * Base del OID de la política de certificados de pe en dispositivo software
	 */
	public static final String POLICY_IN_SOFTWARE_DEVICE = "1.3.6.1.4.1.8149.3.25";

	/**
	 * Base del OID de la política de certificados de pe en la nube
	 */
	public static final String POLICY_IN_CLOUD = "1.3.6.1.4.1.8149.3.26";

	/**
	 * OID del campo con el cargo del empleado de empresa
	 */
	public static final String OID_CARGO_EMPLEADO_EMPRESA	= "1.3.6.1.4.1.8149.4.2.11"; 
	
	/**
	 * OID del campo con el CIF de la entidad suscriptora
	 */
	public static final String OID_CIF_ENTIDAD	= "1.3.6.1.4.1.8149.4.2.3"; 
	
	/**
	 * OID del campo con el nombre de la entidad
	 */
	public static final String OID_NOMBRE_ENTIDAD	= "1.3.6.1.4.1.8149.4.2.2"; 
	
	/**
	 * OID del campo con la unidad del empleado de empresa
	 */
	public static final String OID_UNIDAD_EMPLEADO_EMPRESA	= "1.3.6.1.4.1.8149.4.2.10"; 
	
	/**
	 * OID del campo con el número de empleado
	 */
	public static final String OID_NUMERO_EMPLEADO_EMPRESA	= "1.3.6.1.4.1.8149.4.2.5"; 
	
	/**
	 * Alias del keystore donde se guarda el certificado
	 */
	public static final String ALIAS_PKCS11 = "EMP1";

	/*
	 * Lista de SKI de los certificados de CA de explotación
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
	 * 	reconocido por el proveedor criptográfico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 */
	public CertificadoPertenenciaEmpresa(X509Certificate certificate) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(certificate, getCAList());
	}
	
	/**
	 * Constructor con un fichero que contiene un certificado
	 * 
	 * @param fileCertificate Fichero que contiene un certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptográfico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 * @throws FileNotFoundException El fichero no existe
	 */
	public CertificadoPertenenciaEmpresa(File fileCertificate) throws CertificateCANotFoundException, NormalizeCertificateException, FileNotFoundException {
		super(fileCertificate, getCAList());
	}
	
	/**
	 * Constructor con un fichero que contiene un certificado
	 * 
	 * @param isCertificate Stream de lectura a un certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptográfico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 */
	public CertificadoPertenenciaEmpresa(InputStream isCertificate) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(isCertificate, getCAList());
	}
	
	/**
	 * Constructor con un fichero que contiene un certificado
	 * 
	 * @param contenidoCertificado Contenido de un certificado en formato X.509
	 * @throws CertificateCANotFoundException No se ha encontrado alguno de los certificados de
	 * las CA que tratan este certificado en el classpath
	 * @throws NormalizeCertificateException El certificado no puede ser normalizado al formato
	 * 	reconocido por el proveedor criptográfico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 */
	public CertificadoPertenenciaEmpresa(byte[] contenidoCertificado) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(contenidoCertificado, getCAList());
	}
	
	//-- Métodos de empresas
	
	/**
	 * Comprueba si el certificado es de una CA de test
	 * 
	 * @return Cierto si el certificado es de una CA de test
	 */
	public boolean isTestCertificate () {
		logger.debug("[CertificadoPertenenciaEmpresa.isTestCertificate]::Entrada");
		return setTestCACertificates.contains(getIssuerKeyIdentifier());
	}
	
	/**
	 * Método que devuelve el nombre del titular del certificado
	 * 
	 * @return Nombre del titular del certificado
	 */
	public String getName () {
		return getElementSubject(X509Name.GIVENNAME);
	}
	
	/**
	 * Método que devuelve el primer apellido del titular del certificado
	 * 
	 * @return Primer apellido del titular del certificado
	 */
	public String getFirstSurname () {
		
		logger.debug ("[CertificadoPertenenciaEmpresa.getFirstSurname]::Entrada");
		
		return getNombreCompleto()[1].trim();
	}
	
	/**
	 * Método que devuelve el segundo apellido del titular del certificado
	 * 
	 * @return Segundo apellido del titular del certificado
	 */
	public String getSecondSurname () {
		
		logger.debug ("[CertificadoPertenenciaEmpresa.getSecondSurname]::Entrada");
		
		String[] nombreCompleto = getNombreCompleto();
		
		//-- El segundo apellido no es obligatorio
		if (nombreCompleto == null || nombreCompleto.length < 3) {
			return "";
		}
		
		return nombreCompleto[2].trim();
	}
	
	/**
	 * Método que devuelve los apellidos del titular del certificado
	 * 
	 * @return Apellidos del titular del certificado
	 */
	public String getSurnames () {
		
		logger.debug ("[CertificadoPertenenciaEmpresa.getSurnames]::Entrada");
		
		return getFirstSurname() + " " + getSecondSurname();
	}
	
	/**
	 * Método que devuelve el NIF del titular del certificado
	 * 
	 * @return NIF del titular del certificado
	 */
	public String getNIF () {
		try {
			return getSubjectAlternativeNameElement(OID_USERID);
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoPertenenciaEmpresa.getNIF]::No se puede obtener el NIF", e);
			return null;
		}
	}
	
	/**
	 * Método que devuelve la dirección de correo electrónico del titular del certificado
	 * 
	 * @return E-mail del titular del certificado
	 */
	public String getEmail () {
		
		logger.debug ("[CertificadoPertenenciaEmpresa.getEmail]::Entrada");
		
		List altNames;
		try {
			altNames = getSubjectAlternativeName();
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoPertenenciaEmpresa.getEmail]::No ha sido posible obtener el e-mail del empleado de empresa", e);
			return null;
		}
	
		//-- Es el primer elemento del nombre alternativo
		return (String) ((AlternativeNameElement) altNames.get(0)).getValue();
	}
	
	/**
	 * Método que obtiene el cargo del Empleado de Empresa.
	 * 
	 * @return Cargo del Empleado de Empresa
	 */
	public String getPosition() {
		
		logger.debug ("[CertificadoPertenenciaEmpresa.getCargo]::Entrada");
		
		try {
			return getSubjectAlternativeNameElement(OID_CARGO_EMPLEADO_EMPRESA);
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoPertenenciaEmpresa.getCargo]::No se puede obtener el cargo del empleado de empresa", e);
			return null;
		}
	}
	
	/**
	 * Método que obtiene el valor diferenciador para este tipo
	 * de certificados
	 */
	public String getNRPPseudonym() {
		return getIDNumber();
	}
	
	/**
	 * Método que obtiene el número de identificación del Empleado de Empresa.
	 * 
	 * @return Número de identificación del empleado de empresa
	 */
	public String getIDNumber() {
		
		logger.debug ("[CertificadoPertenenciaEmpresa.getIDNumber]::Entrada");
		
		try {
			return getSubjectAlternativeNameElement(OID_NUMERO_EMPLEADO_EMPRESA);
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoPertenenciaEmpresa.getIDNumber]::No se puede obtener el número de identificación del empleado de empresa", e);
			return null;
		}
	}
	
	/**
	 * Método que obtiene el CIF de la entidad suscriptora del certificado.
	 * 
	 * @return CIF de la entidad suscriptora del certificado
	 */
	public String getEntityCIF() {
		
		logger.debug ("[CertificadoPertenenciaEmpresa.getCIFEntidad]::Entrada");
		
		try {
			return getSubjectAlternativeNameElement(OID_CIF_ENTIDAD);
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoPertenenciaEmpresa.getCargo]::No se puede obtener el cif de la entidad suscriptora", e);
			return null;
		}
	}
	
	/**
	 * Método que obtiene el nombre de la entidad suscriptora del certificado.
	 * 
	 * @return Nombre de la entidad suscriptora del certificado
	 */
	public String getEntityName() {
		
		logger.debug ("[CertificadoPertenenciaEmpresa.getNombreEntidad]::Entrada");
		
		try {
			return getSubjectAlternativeNameElement(OID_NOMBRE_ENTIDAD);
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoPertenenciaEmpresa.getCargo]::No se puede obtener el nombre de la entidad suscriptora", e);
			return null;
		}
	}
	
	/**
	 * Devuelve la Unidad, dentro de la Administración, en la que está incluida el suscriptor
	 * del certificado.
	 * 
	 * @return Organization Unit del titular del certificado.
	 */
	public String getOrganizationalUnit() {
		
		logger.debug ("[CertificadoPertenenciaEmpresa.getOrganizationalUnit]::Entrada");

	    try {
			return getSubjectAlternativeNameElement(OID_UNIDAD_EMPLEADO_EMPRESA);
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoPertenenciaEmpresa.getCargo]::No se puede obtener la unidad del empleado de empresa", e);
			return null;
		}
	}
	
	/**
	 * El certificado se encuentra en un dispositivo PKCS#11
	 * 
	 * @return Cierto si el certificado se encuentra en un dispositivo PKCS#11
	 */
	public boolean isInPkcs11Device () {
		logger.debug ("[CertificadoPertenenciaEmpresa.isInPkcs11Device]::Entrada");
		
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
		logger.debug ("[CertificadoPertenenciaEmpresa.isInSoftwareDevice]::Entrada");
		
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
		logger.debug ("[CertificadoPertenenciaEmpresa.isInCloud]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_IN_CLOUD)) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Método que indica si el certificado es válido para el cifrado de datos: NO
	 * 
	 * @return Cierto si el certificado es válido para el cifrado de datos
	 */
	public boolean isCipherCertificate() {
		return false;
	}

	/**
	 * Método que indica si el certificado es válido para la firma digital:SI
	 * 
	 * @return Cierto si el certificado es válido para la firma digital
	 */
	public boolean isSigningCertificate() {
		return true;
	}
	
	/**
	 * Obtiene la lista de certificados de CA y raíz que conforman las posibles cadenas
	 * de confianza de los certificados de esta clase. 
	 */
	public static CAList getCAList() throws CertificateCANotFoundException {
		
		//-- Añadir los certificados de test y de explotación
		List lCACertificates = getCAListExlotation();
		lCACertificates.addAll(getCAListTest());
		
		CAList caList;
		try {
			caList = new CAList (lCACertificates);
		} catch (NormalizeCertificateException e) {
			//-- Si algún certificado no puede ser normalizado lo pasamos como que no
			//-- se ha podido cargar
			logger.info ("[CertificadoPertenenciaEmpresa.getCAList]::Alguno de los certificados de las CA no ha podido ser " +
					"normalizado a lo esperado por el proveedor criptográfico de Arangi", e);
			throw new CertificateCANotFoundException ("Alguno de los certificados de las CA no ha podido ser " +
					"normalizado a lo esperado por el proveedor criptográfico de Arangi", e);
		};
		
		//-- Añadir el fichero para validar los certificados de test
		try {
			caList.setValidationXML(ArangiUtil.loadFile("file/validation_data_accv_test.xml"));
		} catch (ValidationXMLException e) {
			//-- Si no se ha podido parsear el fichero de validación lo pasamos como que
			//-- no se han podido cargar los certificados de las CA
			logger.info ("[CertificadoPertenenciaEmpresa.getCAList]::No ha sido posible parsear el fichero de validación XML", e);
			throw new CertificateCANotFoundException ("No ha sido posible parsear el fichero de validación XML", e);
		} catch (ResourceNotLoadedException e) {
			//-- Si no se encuentra pasaremos sin él, sólo que no funcionarán los certificados de test
			logger.info ("[CertificadoPertenenciaEmpresa.getCAList]::No ha sido posible obtener el fichero de validación XML", e);
		}
		
		return caList;
	}

	//-- Métodos protected
	
	/**
	 * Usado por la clase CertificateFactory para dar de alta la clase en la lista
	 * de tipos de certificados.
	 * 
	 * @return OID base de la política
	 */
	protected static String[] getBasePolicies () {
		return new String[] { 
			POLICY_IN_PKCS11_DEVICE, // certificados en tarjeta
			POLICY_IN_SOFTWARE_DEVICE, // certificados en software
			POLICY_IN_CLOUD // certificados en la nube 
		};
	}

	//-- Métodos privados
	
	/*
	 * Obtiene la lista de certificados de CA y raíz que conforman las posibles cadenas
	 * de confianza de los certificados de explotación de esta clase. 
	 */
	private static List getCAListExlotation() throws CertificateCANotFoundException {
		
		//-- Añadir los certificados de explotación
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
	 * Obtiene la lista de certificados de CA y raíz que conforman las posibles cadenas
	 * de confianza de los certificados de test de esta clase. 
	 */
	private static List getCAListTest() throws CertificateCANotFoundException {
		
		//-- Añadir los certificados de test y de explotación
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
	 * Obtiene el nombre completo que hay en la extensión Subject Alternative Name como
	 * entrada del LDAP. El array tendrá 3 elementos: nombre, apellido 1 y apellido 2
	 */
	private String [] getNombreCompleto () {
		
		String nombreCompleto;
		try {
			nombreCompleto = getSubjectAlternativeNameElement(OID_ID_AT_COMMONNAME);
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoPertenenciaEmpresa.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		if (nombreCompleto == null || nombreCompleto.length() == 0) {
			logger.info ("[CertificadoPertenenciaEmpresa.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		return nombreCompleto.split("\\|");

	}

	
	

}
