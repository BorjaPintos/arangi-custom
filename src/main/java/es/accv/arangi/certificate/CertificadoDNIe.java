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
 * Clase para el tratamiento de los certificados del DNIe seg�n 
 * la pol�tica definida en la URL: <a href="http://www.dnie.es/dpc" target="politica">
 * http://www.dnie.es/dpc</a><br><br>
 * 
 * Se emiten dos tipos de certificados del DNIe:<br>
 * <ul>
 * 	<li>De firma: OID de la pol�tica=2.16.724.1.2.2.2.3</li>
 * 	<li>De autenticaci�n: OID de la pol�tica=2.16.724.1.2.2.2.4</li>
 * </ul>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class CertificadoDNIe extends CertificadoPersona {

	/**
	 * OID de la pol�tica de los certificados del DNIe de firma
	 */
	public static final String OID_POLICY_SIGNING 			= "2.16.724.1.2.2.2.3";
	
	/**
	 * OID de la pol�tica de los certificados del DNIe de autenticaci�n
	 */
	public static final String OID_POLICY_AUTHENTICATION 	= "2.16.724.1.2.2.2.4";
	
	/**
	 * Alias del keystore donde se guarda el certificado de firma
	 */
	public static final String ALIAS_PKCS11_FIRMA = "CertFirmaDigital";

	/**
	 * Alias del keystore donde se guarda el certificado de autenticaci�n
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
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
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
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
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
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
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
	 * 	reconocido por el proveedor criptogr�fico de Arangi o su firma no es correcta o no
	 * 	puede ser analizada
	 */
	public CertificadoDNIe(byte[] contenidoCertificado) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(contenidoCertificado, getCAList());
	}
	
	//-- M�todos p�blicos
	
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
	 * M�todo que devuelve el nombre de la aplicaci�n
	 * 
	 * @return Nombre de la entidad
	 */
	public String getName () {
		logger.debug ("[CertificadoDNIe.getName]::Entrada");
		return getElementSubject(X509Name.GIVENNAME);
	}
	
	/**
	 * M�todo que devuelve el primer apellido del titular del certificado
	 * 
	 * @return Primer apellido del titular del certificado
	 */
	public String getFirstSurname () {
		logger.debug ("[CertificadoDNIe.getFirstSurname]::Entrada");
		return getElementSubject(X509Name.SURNAME);
	}
	
	/**
	 * M�todo que devuelve el segundo apellido del titular del certificado
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
	 * M�todo que devuelve los apellidos del titular del certificado
	 * 
	 * @return Apellidos del titular del certificado
	 */
	public String getSurnames () {
		
		logger.debug ("[CertificadoDNIe.getSurnames]::Entrada");
		
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
	 * Determina si el certificado del DNIe es de firma
	 * 
	 * @return Cierto si el certificado es de firma
	 */
	public boolean isSigningCertificate () {
		return getPolicyOID().equals(OID_POLICY_SIGNING);
	}
	
	/**
	 * Determina si el certificado del DNIe es de autenticaci�n
	 * 
	 * @return Cierto si el certificado es de autenticaci�n
	 */
	public boolean isAuthenticationCertificate () {
		return getPolicyOID().equals(OID_POLICY_AUTHENTICATION);
	}
	
	/**
	 * M�todo que devuelve la direcci�n de correo electr�nico del titular del certificado.
	 * En el caso del DNIe este dato no existe
	 * 
	 * @return Null
	 */
	public String getEmail() {
		return null;
	}

	/**
	 * M�todo que indica si el certificado es v�lido para el cifrado de datos: NO
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
	 * Obtiene la lista de certificados de CA y ra�z que conforman las posibles cadenas
	 * de confianza de los certificados de esta clase. 
	 */
	public static CAList getCAList() throws CertificateCANotFoundException {
		
		//-- A�adir los certificados de test y de explotaci�n
		List lCACertificates = getCAListExlotation();
		
		CAList caList;
		try {
			caList = new CAList (lCACertificates);
		} catch (NormalizeCertificateException e) {
			//-- Si alg�n certificado no puede ser normalizado lo pasamos como que no
			//-- se ha podido cargar
			logger.info ("[CertificadoDNIe.getCAList]::Alguno de los certificados de las CA no ha podido ser " +
					"normalizado a lo esperado por el proveedor criptogr�fico de Arangi", e);
			throw new CertificateCANotFoundException ("Alguno de los certificados de las CA no ha podido ser " +
					"normalizado a lo esperado por el proveedor criptogr�fico de Arangi", e);
		};
		
		//-- A�adir el fichero para validar los certificados de test
		try {
			caList.setValidationXML(ArangiUtil.loadFile("file/validation_data_dnie.xml"));
		} catch (ValidationXMLException e) {
			//-- Si no se ha podido parsear el fichero de validaci�n lo pasamos como que
			//-- no se han podido cargar los certificados de las CA
			logger.info ("[CertificadoDNIe.getCAList]::No ha sido posible parsear el fichero de validaci�n XML", e);
			throw new CertificateCANotFoundException ("No ha sido posible parsear el fichero de validaci�n XML", e);
		} catch (ResourceNotLoadedException e) {
			//-- Si no se encuentra pasaremos sin �l, s�lo que no funcionar�n los certificados de test
			logger.info ("[CertificadoDNIe.getCAList]::No ha sido posible obtener el fichero de validaci�n XML", e);
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
		return new String[] {OID_POLICY_SIGNING, OID_POLICY_AUTHENTICATION};
	}

	//-- M�todos privados
	
	/*
	 * Obtiene la lista de certificados de CA y ra�z que conforman las posibles cadenas
	 * de confianza de los certificados de explotaci�n de esta clase. 
	 */
	private static List getCAListExlotation() throws CertificateCANotFoundException {
		
		//-- A�adir los certificados de test y de explotaci�n
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
	 * Obtiene el nombre completo que hay en la extensi�n Subject Alternative Name como
	 * entrada del LDAP. El array tendr� 3 elementos: nombre, apellido 1 y apellido 2
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
