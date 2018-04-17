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
import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.X509Name;

import es.accv.arangi.base.certificate.Certificate;
import es.accv.arangi.base.certificate.validation.CAList;
import es.accv.arangi.base.exception.certificate.CertificateCANotFoundException;
import es.accv.arangi.base.exception.certificate.CertificateFieldException;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.certificate.ValidationXMLException;
import es.accv.arangi.base.util.AlternativeNameElement;
import es.accv.arangi.certificate.field.DatosRepresentacionBoletinOficial;
import es.accv.arangi.certificate.field.DatosRepresentacionDesconocido;
import es.accv.arangi.certificate.field.DatosRepresentacionRegistro;
import es.accv.arangi.certificate.field.DatosRepresentacionRegistroNotarial;
import es.accv.arangi.exception.ResourceNotLoadedException;
import es.accv.arangi.util.ArangiUtil;

/**
 * Clase para el tratamiento de los certificados reconocidos de representante de la ACCV, según la 
 * política definida en la URL: 
 * <a href="http://www.accv.es/quienes-somos/practicas-y-politicas-de-certificacion/politicas-de-certificacion/" target="politica">
 * http://www.accv.es/quienes-somos/practicas-y-politicas-de-certificacion/politicas-de-certificacion/</a>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class CertificadoRepresentante extends CertificadoPersona{

	/*
	 * Logger de la clas
	 */
	static Logger logger = Logger.getLogger(CertificadoRepresentante.class);
	
	/**
	 * Alias del keystore donde se guarda el certificado
	 */
	public static final String ALIAS_PKCS11 = "REPR";

	/**
	 * Base del OID de la política de certificados de ep en dispositivo seguro
	 */
	public static final String POLICY_WITH_IN_PKCS11_DEVICE = "1.3.6.1.4.1.8149.3.29";

	/**
	 * Base del OID de la política de certificados de ep en dispositivo software
	 */
	public static final String POLICY_WITH_IN_SOFTWARE_DEVICE = "1.3.6.1.4.1.8149.3.30";

	/**
	 * Base del OID de la política de certificados de ep en dispositivo seguro
	 */
	public static final String POLICY_WITHOUT_IN_PKCS11_DEVICE = "1.3.6.1.4.1.8149.3.31";

	/**
	 * Base del OID de la política de certificados de ep en dispositivo software
	 */
	public static final String POLICY_WITHOUT_IN_SOFTWARE_DEVICE = "1.3.6.1.4.1.8149.3.32";

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
	public CertificadoRepresentante(X509Certificate certificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoRepresentante(File fileCertificate) throws CertificateCANotFoundException, NormalizeCertificateException, FileNotFoundException {
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
	public CertificadoRepresentante(InputStream isCertificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoRepresentante(byte[] contenidoCertificado) throws CertificateCANotFoundException, NormalizeCertificateException {
		super(contenidoCertificado, getCAList());
	}
	
	//-- Métodos públicos
	
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
		
		logger.debug ("[CertificadoRepresentante.getFirstSurname]::Entrada");
		
		return getNombreCompleto()[1].trim();
	}
	
	/**
	 * Método que devuelve el segundo apellido del titular del certificado
	 * 
	 * @return Segundo apellido del titular del certificado
	 */
	public String getSecondSurname () {
		
		logger.debug ("[CertificadoRepresentante.getSecondSurname]::Entrada");
		
		String[] nombreCompleto = getNombreCompleto();
		
		//-- El segundo apellido no es obligatorio
		if (nombreCompleto == null || nombreCompleto.length < 3) {
			return "";
		}
		
		return nombreCompleto[2].trim();
	}
	
	/**
	 * Método que devuelve los apellidos del representante de la entidad
	 * 
	 * @return Apellidos del representante de la entidad
	 */
	public String getSurnames () {
		
		logger.debug ("[CertificadoRepresentante.getSurnames]::Entrada");
		
		return getFirstSurname() + " " + getSecondSurname();
	}
	
	/**
	 * Método que devuelve el NIF del representante de la entidad
	 * 
	 * @return NIF del titular del certificado
	 */
	public String getNIF () {
		
		logger.debug ("[CertificadoRepresentante.getNIF]::Entrada");

		return getElementSubject(BCStyle.SERIALNUMBER);
	}
	
	/**
	 * Método que obtiene el CIF de la entidad.
	 * 
	 * @return CIF de la entidad
	 */
	public String getEntityCIF() {
		
		logger.debug ("[CertificadoRepresentante.getCIF]::Entrada");
		
		return getElementSubject(new ASN1ObjectIdentifier("2.5.4.97")).replace("VATES-", "");
	}
	
	/**
	 * Método que obtiene el CIF de la entidad codificado según el ETSI
	 * (sólo para certificados cualificados de sello de entidad).
	 * 
	 * @return CIF de la entidad según el ETSI
	 */
	public String getEntityCIFETSI() {
		
		logger.debug ("[CertificadoRepresentante.getEntityCIFETSI]::Entrada");
		
		return getElementSubject(new ASN1ObjectIdentifier("2.5.4.97"));
	}
	
	/**
	 * Método que obtiene el nombre de la entidad.
	 * 
	 * @return Nombre de la entidad
	 */
	public String getEntityName() {
		
		logger.debug ("[CertificadoRepresentante.getEntityName]::Entrada");
		
		return getElementSubject(X509Name.O);
	}
	
	/**
	 * Obtiene la información que relaciona al representante con la entidad en
	 * los certificados cualificados de entidad como una tira de texto.
	 * 
	 * @return Tira de texto con la información de representación
	 */
	public String getRepresentationDataString() {
		return getElementSubject(new ASN1ObjectIdentifier("2.5.4.13"));
	}
	
	/**
	 * Obtiene la información que relaciona al representante con la entidad en
	 * los certificados cualificados de entidad. Estos datos se incluyen en el 
	 * certificado y pueden ser una entrada en un registro, un registro notarial, 
	 * una entrada en un boletín o cualquier otra cosa.<br>
	 * Los certificados generados antes de Julio de 2016 no dispondrán de este
	 * campo.
	 * 
	 * @return En caso de que exista el campo se devolverá un objeto que puede ser
	 * 	de las siguientes clases: DatosRepresentacionRegistro, DatosRepresentacionRegistroNotarial,
	 * 	DatosRepresentacionBoletinOficial o DatosRepresentacionDesconocido. Si el
	 * 	campo no existe se devolverá null.
	 */
	public Object getRepresentationData() {
		String descripcion = getRepresentationDataString();
		logger.debug ("[CertificadoEntidad.getRepresentationData]::Descripcion: " + descripcion);
		if (descripcion == null) {
			return null;
		}
		
		String[] elementos = descripcion.split("/");
		if (descripcion.startsWith("R:")) {
			DatosRepresentacionRegistro datos = new DatosRepresentacionRegistro();
			datos.setRegistro(elementos[0].substring(elementos[0].indexOf(":") + 1));
			datos.setHoja(elementos[1]);
			datos.setTomo(elementos[2]);
			datos.setSeccion(elementos[3]);
			datos.setLibro(elementos[4]);
			datos.setFolio(elementos[5]);
			if (!elementos[6].trim().equals("")) {
				try {
					datos.setFecha(ArangiUtil.SIMPLE_DATE_FORMAT.parse(elementos[6]));
				} catch (ParseException e) {
					logger.info("No se puede parsear la fecha '" + elementos[6] + "");
				}
			}
			datos.setInscripcion(elementos[7]);
			return datos;
		} else if (descripcion.startsWith("N:")) {
			DatosRepresentacionRegistroNotarial datos = new DatosRepresentacionRegistroNotarial();
			datos.setNotario(elementos[0].substring(elementos[0].indexOf(":") + 1));
			datos.setNumeroProtocolo(elementos[1]);
			if (!elementos[2].trim().equals("")) {
				try {
					datos.setFechaOtorgamiento(ArangiUtil.SIMPLE_DATE_FORMAT.parse(elementos[2]));
				} catch (ParseException e) {
					logger.info("No se puede parsear la fecha '" + elementos[6] + "");
				}
			}
			return datos;
		} else if (descripcion.startsWith("B:")) {
			DatosRepresentacionBoletinOficial datos = new DatosRepresentacionBoletinOficial();
			datos.setBoletin(elementos[0].substring(elementos[0].indexOf(":") + 1));
			if (!elementos[1].trim().equals("")) {
				try {
					datos.setFecha(ArangiUtil.SIMPLE_DATE_FORMAT.parse(elementos[1]));
				} catch (ParseException e) {
					logger.info("No se puede parsear la fecha '" + elementos[6] + "");
				}
			}
			datos.setNumeroResolucion(elementos[2]);
			return datos;
		} else {
			DatosRepresentacionDesconocido datos = new DatosRepresentacionDesconocido(descripcion);
			return datos;
		}
	}
	
	/**
	 * Método que devuelve la dirección de correo electrónico de la entidad
	 * 
	 * @return E-mail de la entidad titular del certificado
	 */
	public String getEmail () {
		
		logger.debug ("[CertificadoRepresentante.getEmail]::Entrada");
		
		List altNames;
		try {
			altNames = getSubjectAlternativeName();
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoRepresentante.getEmail]::No ha sido posible obtener el e-mail de la entidad", e);
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
		logger.debug ("[CertificadoRepresentante.isInPkcs11Device]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_WITH_IN_PKCS11_DEVICE) ||
					policyOID.startsWith(POLICY_WITHOUT_IN_PKCS11_DEVICE)) {
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
		logger.debug ("[CertificadoRepresentante.isInSoftwareDevice]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_WITH_IN_SOFTWARE_DEVICE) ||
					policyOID.startsWith(POLICY_WITHOUT_IN_SOFTWARE_DEVICE)) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * El certificado se emitió para una entidad con personalidad jurídica
	 * 
	 * @return Cierto si el certificado se emitió para una entidad con personalidad jurídica
	 */
	public boolean isWithLegalPersonality () {
		logger.debug ("[CertificadoRepresentante.isWithLegalPersonality]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_WITH_IN_PKCS11_DEVICE) ||
					policyOID.startsWith(POLICY_WITH_IN_SOFTWARE_DEVICE)) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * El certificado se emitió para una entidad sin personalidad jurídica
	 * 
	 * @return Cierto si el certificado se emitió para una entidad sin personalidad jurídica
	 */
	public boolean isWithoutLegalPersonality () {
		logger.debug ("[CertificadoRepresentante.isWithoutLegalPersonality]::Entrada");
		
		for (String policyOID : getPolicyOIDs()) {
			if (policyOID.startsWith(POLICY_WITHOUT_IN_PKCS11_DEVICE) ||
					policyOID.startsWith(POLICY_WITHOUT_IN_SOFTWARE_DEVICE)) {
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
	 * Obtiene la lista de certificados de CA y raíz que conforman las posibles cadenas
	 * de confianza de los certificados de esta clase. 
	 */
	public static CAList getCAList() throws CertificateCANotFoundException {
		
		//-- Añadir los certificados de test y de explotación
		List lCACertificates = getCAListExplotation();
		lCACertificates.addAll(getCAListTest());
		
		CAList caList;
		try {
			caList = new CAList (lCACertificates);
		} catch (NormalizeCertificateException e) {
			//-- Si algún certificado no puede ser normalizado lo pasamos como que no
			//-- se ha podido cargar
			logger.info ("[CertificadoRepresentante.getCAList]::Alguno de los certificados de las CA no ha podido ser " +
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
			logger.info ("[CertificadoRepresentante.getCAList]::No ha sido posible parsear el fichero de validación XML", e);
			throw new CertificateCANotFoundException ("No ha sido posible parsear el fichero de validación XML", e);
		} catch (ResourceNotLoadedException e) {
			//-- Si no se encuentra pasaremos sin él, sólo que no funcionarán los certificados de test
			logger.info ("[CertificadoRepresentante.getCAList]::No ha sido posible obtener el fichero de validación XML", e);
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
		return new String[] { 
				POLICY_WITH_IN_PKCS11_DEVICE, // certificados en tarjeta
				POLICY_WITH_IN_SOFTWARE_DEVICE, // certificados en software
				POLICY_WITHOUT_IN_PKCS11_DEVICE, // certificados en tarjeta
				POLICY_WITHOUT_IN_SOFTWARE_DEVICE // certificados en software
		};
	}

	//-- Métodos privados
	
	/*
	 * Obtiene la lista de certificados de CA y raíz que conforman las posibles cadenas
	 * de confianza de los certificados de explotación de esta clase. 
	 */
	private static List getCAListExplotation() throws CertificateCANotFoundException {
		
		//-- Añadir los certificados de explotación
		List lCACertificates = new ArrayList ();
		X509Certificate certificate = ArangiUtil.loadCertificate("certificate/ACCV-CA120-SHA256");
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
		X509Certificate certificate = ArangiUtil.loadCertificate("certificate/ACCVCATEST120");
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
			logger.info ("[CertificadoRepresentante.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		if (nombreCompleto == null || nombreCompleto.length() == 0) {
			logger.info ("[CertificadoRepresentante.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		return nombreCompleto.split("\\|");

	}

}
