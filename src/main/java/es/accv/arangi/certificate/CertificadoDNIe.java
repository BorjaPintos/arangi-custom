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
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.X509Name;

import es.accv.arangi.base.certificate.validation.CAList;
import es.accv.arangi.base.exception.certificate.CertificateCANotFoundException;
import es.accv.arangi.base.exception.certificate.CertificateFieldException;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.certificate.ValidationXMLException;
import es.accv.arangi.exception.ResourceNotLoadedException;
import es.accv.arangi.util.ArangiUtil;

/**
 * Clase para el tratamiento de los certificados del DNIe según 
 * la política definida en la URL: <a href="http://www.dnie.es/dpc" target="politica">
 * http://www.dnie.es/dpc</a><br><br>
 * 
 * Se emiten dos tipos de certificados del DNIe:<br>
 * <ul>
 * 	<li>De firma: OID de la política=2.16.724.1.2.2.2.3</li>
 * 	<li>De autenticación: OID de la política=2.16.724.1.2.2.2.4</li>
 * </ul>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class CertificadoDNIe extends CertificadoPersona {

	/**
	 * OID de la política de los certificados del DNIe de firma
	 */
	public static final String OID_POLICY_SIGNING 			= "2.16.724.1.2.2.2.3";
	
	/**
	 * OID de la política de los certificados del DNIe de autenticación
	 */
	public static final String OID_POLICY_AUTHENTICATION 	= "2.16.724.1.2.2.2.4";
	
	/**
	 * Alias del keystore donde se guarda el certificado de firma
	 */
	public static final String ALIAS_PKCS11_FIRMA = "CertFirmaDigital";

	/**
	 * Alias del keystore donde se guarda el certificado de autenticación
	 */
	public static final String ALIAS_PKCS11_AUTENTICACION = "CertAutenticacion";

	/*
	 * Logger de la clase
	 */
	static Logger logger = Logger.getLogger(CertificadoDNIe.class);
	
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
	public CertificadoDNIe(X509Certificate certificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoDNIe(File fileCertificate) throws CertificateCANotFoundException, NormalizeCertificateException, FileNotFoundException {
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
	public CertificadoDNIe(InputStream isCertificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoDNIe(byte[] contenidoCertificado) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(contenidoCertificado, getCAList());
	}
	
	//-- Métodos públicos
	
	/**
	 * Comprueba si el certificado es de una CA de test
	 * 
	 * @return Cierto si el certificado es de una CA de test
	 */
	public boolean isTestCertificate () {
		logger.debug("[CertificadoDNIe.isTestCertificate]::Entrada");
		return false;
	}
	
	/**
	 * Método que devuelve el nombre de la aplicación
	 * 
	 * @return Nombre de la entidad
	 */
	public String getName () {
		logger.debug ("[CertificadoDNIe.getName]::Entrada");
		return getElementSubject(X509Name.GIVENNAME);
	}
	
	/**
	 * Método que devuelve el primer apellido del titular del certificado
	 * 
	 * @return Primer apellido del titular del certificado
	 */
	public String getFirstSurname () {
		logger.debug ("[CertificadoDNIe.getFirstSurname]::Entrada");
		return getElementSubject(X509Name.SURNAME);
	}
	
	/**
	 * Método que devuelve el segundo apellido del titular del certificado
	 * 
	 * @return Segundo apellido del titular del certificado
	 */
	public String getSecondSurname () {
		
		logger.debug ("[CertificadoDNIe.getSecondSurname]::Entrada");
		
		//-- Obtengo el common name y el primer apellido
		String cn = getCommonName();
		String firstSurname = getFirstSurname ();
		
		//-- El segundo apellido va desde el fin del primero a la coma
		return cn.substring(firstSurname.length() + 1, cn.indexOf(",")).trim();
	}
	
	/**
	 * Método que devuelve los apellidos del titular del certificado
	 * 
	 * @return Apellidos del titular del certificado
	 */
	public String getSurnames () {
		
		logger.debug ("[CertificadoDNIe.getSurnames]::Entrada");
		
		return getFirstSurname() + " " + getSecondSurname();
	}
	
	/**
	 * Método que devuelve el NIF del titular del certificado
	 * 
	 * @return NIF del titular del certificado
	 */
	public String getNIF () {
		return getElementSubject(BCStyle.SERIALNUMBER);
	}
	
	/**
	 * Determina si el certificado del DNIe es de firma
	 * 
	 * @return Cierto si el certificado es de firma
	 */
	public boolean isSigningCertificate () {
		return getPolicyOID().equals(OID_POLICY_SIGNING);
	}
	
	/**
	 * Determina si el certificado del DNIe es de autenticación
	 * 
	 * @return Cierto si el certificado es de autenticación
	 */
	public boolean isAuthenticationCertificate () {
		return getPolicyOID().equals(OID_POLICY_AUTHENTICATION);
	}
	
	/**
	 * Método que devuelve la dirección de correo electrónico del titular del certificado.
	 * En el caso del DNIe este dato no existe
	 * 
	 * @return Null
	 */
	public String getEmail() {
		return null;
	}

	/**
	 * Método que indica si el certificado es válido para el cifrado de datos: NO
	 * 
	 * @return Falso
	 */
	public boolean isCipherCertificate() {
		return false;
	}

	/**
	 * El certificado se encuentra en un dispositivo PKCS#11: SI
	 * 
	 * @return Cierto 
	 */
	public boolean isInPkcs11Device() {
		return true;
	}

	/**
	 * El certificado se encuentra en un dispositivo software (PKCS#12): NO
	 * 
	 * @return Falso
	 */
	public boolean isInSoftwareDevice() {
		return false;
	}

	/**
	 * Obtiene la lista de certificados de CA y raíz que conforman las posibles cadenas
	 * de confianza de los certificados de esta clase. 
	 */
	public static CAList getCAList() throws CertificateCANotFoundException {
		
		//-- Añadir los certificados de test y de explotación
		List lCACertificates = getCAListExlotation();
		
		CAList caList;
		try {
			caList = new CAList (lCACertificates);
		} catch (NormalizeCertificateException e) {
			//-- Si algún certificado no puede ser normalizado lo pasamos como que no
			//-- se ha podido cargar
			logger.info ("[CertificadoDNIe.getCAList]::Alguno de los certificados de las CA no ha podido ser " +
					"normalizado a lo esperado por el proveedor criptográfico de Arangi", e);
			throw new CertificateCANotFoundException ("Alguno de los certificados de las CA no ha podido ser " +
					"normalizado a lo esperado por el proveedor criptográfico de Arangi", e);
		};
		
		//-- Añadir el fichero para validar los certificados de test
		try {
			caList.setValidationXML(ArangiUtil.loadFile("file/validation_data_dnie.xml"));
		} catch (ValidationXMLException e) {
			//-- Si no se ha podido parsear el fichero de validación lo pasamos como que
			//-- no se han podido cargar los certificados de las CA
			logger.info ("[CertificadoDNIe.getCAList]::No ha sido posible parsear el fichero de validación XML", e);
			throw new CertificateCANotFoundException ("No ha sido posible parsear el fichero de validación XML", e);
		} catch (ResourceNotLoadedException e) {
			//-- Si no se encuentra pasaremos sin él, sólo que no funcionarán los certificados de test
			logger.info ("[CertificadoDNIe.getCAList]::No ha sido posible obtener el fichero de validación XML", e);
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
	protected static String [] getBasePolicies () {
		return new String[] {OID_POLICY_SIGNING, OID_POLICY_AUTHENTICATION};
	}

	//-- Métodos privados
	
	/*
	 * Obtiene la lista de certificados de CA y raíz que conforman las posibles cadenas
	 * de confianza de los certificados de explotación de esta clase. 
	 */
	private static List getCAListExlotation() throws CertificateCANotFoundException {
		
		//-- Añadir los certificados de test y de explotación
		List lCACertificates = new ArrayList ();
		X509Certificate certificate = ArangiUtil.loadCertificate("certificate/ACDNIE001-SHA2");
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ACDNIE002-SHA2");
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ACDNIE003-SHA2");
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ACDNIE004-SHA2");
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ACDNIE005-SHA2");
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ACDNIE006-SHA2");
		lCACertificates.add(certificate);
		
		certificate = ArangiUtil.loadCertificate("certificate/ACRAIZ-SHA2");
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
			logger.info ("[CertificadoDNIe.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		if (nombreCompleto == null || nombreCompleto.length() == 0) {
			logger.info ("[CertificadoDNIe.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		return nombreCompleto.split("\\|");

	}

	
}
