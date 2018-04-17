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
 * Clase para el tratamiento de los certificados de aplicación de la ACCV según 
 * la política definida en la URL: <a href="http://www.accv.es/pdf-politicas/PKIGVA-CP-05V3.1-c.pdf" target="politica">
 * http://www.accv.es/pdf-politicas/PKIGVA-CP-05V3.1-c.pdf</a>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class CertificadoAplicacion extends CertificadoACCV {

	/*
	 * Logger de la clase
	 */
	static Logger logger = Logger.getLogger(CertificadoAplicacion.class);
	
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
	public CertificadoAplicacion(X509Certificate certificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoAplicacion(File fileCertificate) throws CertificateCANotFoundException, NormalizeCertificateException, FileNotFoundException {
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
	public CertificadoAplicacion(InputStream isCertificate) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	public CertificadoAplicacion(byte[] contenidoCertificado) throws CertificateCANotFoundException, NormalizeCertificateException {
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
	 * Método que devuelve el nombre de la aplicación
	 * 
	 * @return Nombre de la entidad
	 */
	public String getName () {
		
		logger.debug ("[CertificadoAplicacion.getName]::Entrada");
		
		//-- Obtener el common name
		String name = getCommonName();
		
		//-- El nombre es lo que queda a la izquierda del -
		if (name.indexOf("-") == -1) {
			return name; // raro raro
		}
		
		return name.split("-")[0].trim();
	}
	
	/**
	 * Método que devuelve el servicio al que pertenece de la aplicación
	 * 
	 * @return Nombre del servicio al que pertenece de la aplicación
	 */
	public String getService () {
		
		logger.debug ("[CertificadoAplicacion.getName]::getService");
		
		//-- Obtener el common name
		String name = getCommonName();
		
		//-- El nombre es lo que queda a la izquierda del -
		if (name.indexOf("-") == -1) {
			return ""; // raro raro
		}
		
		return name.split("-")[1].trim();
	}
	
	/**
	 * Método que devuelve el nombre del responsable de la aplicación
	 * 
	 * @return Nombre del responsable de la aplicación
	 */
	public String getResponsibleName () {
		
		logger.debug ("[CertificadoAplicacion.getResponsibleName]::Entrada");
		
		return getNombreCompleto()[0].trim();
	}
	
	/**
	 * Método que devuelve el primer apellido del responsable de la aplicación
	 * 
	 * @return Primer apellido del responsable de la aplicación
	 */
	public String getResponsibleFirstSurname () {
		
		logger.debug ("[CertificadoAplicacion.getResponsibleFirstSurname]::Entrada");
		
		return getNombreCompleto()[1].trim();
	}
	
	/**
	 * Método que devuelve el segundo apellido del responsable de la aplicación
	 * 
	 * @return Segundo apellido del responsable de la aplicación
	 */
	public String getResponsibleSecondSurname () {
		
		logger.debug ("[CertificadoAplicacion.getResponsibleSecondSurname]::Entrada");
		
		return getNombreCompleto()[2].trim();
	}
	
	/**
	 * Método que devuelve los apellidos del responsable de la aplicación
	 * 
	 * @return Apellidos del responsable de la aplicación
	 */
	public String getResponsibleSurnames () {
		
		logger.debug ("[CertificadoAplicacion.getResponsibleSurnames]::Entrada");
		
		return getResponsibleFirstSurname() + " " + getResponsibleSecondSurname();
	}
	
	/**
	 * Método que devuelve la dirección de correo electrónico de la entidad
	 * responsable de la aplicación
	 * 
	 * @return E-mail de la entidad responsable
	 */
	public String getEmail () {
		
		logger.debug ("[CertificadoAplicacion.getEmail]::Entrada");
		
		List altNames;
		try {
			altNames = getSubjectAlternativeName();
		} catch (CertificateFieldException e) {
			logger.info ("[CertificadoAplicacion.getEmail]::No ha sido posible obtener el e-mail de la entidad", e);
			return null;
		}
	
		//-- Es el primer elemento del nombre alternativo
		return (String) ((AlternativeNameElement) altNames.get(0)).getValue();
	}
	
	@Override
	public boolean isCipherCertificate() {
		return false;
	}

	@Override
	public boolean isSigningCertificate() {
		return true;
	}

	@Override
	public boolean isInPkcs11Device() {
		return false;
	}

	@Override
	public boolean isInSoftwareDevice() {
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
			logger.info ("[CertificadoAplicacion.getCAList]::Alguno de los certificados de las CA no ha podido ser " +
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
			logger.info ("[CertificadoAplicacion.getCAList]::No ha sido posible parsear el fichero de validación XML", e);
			throw new CertificateCANotFoundException ("No ha sido posible parsear el fichero de validación XML", e);
		} catch (ResourceNotLoadedException e) {
			//-- Si no se encuentra pasaremos sin él, sólo que no funcionarán los certificados de test
			logger.info ("[CertificadoAplicacion.getCAList]::No ha sido posible obtener el fichero de validación XML", e);
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
		return new String[] {"1.3.6.1.4.1.8149.3.5"};
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
			logger.info ("[CertificadoAplicacion.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		if (nombreCompleto == null || nombreCompleto.length() == 0) {
			logger.info ("[CertificadoAplicacion.getNombreCompleto]::No ha sido posible obtener el nombre completo del ciudadano");
			return null;
		}
		return nombreCompleto.split("\\|");

	}

}
