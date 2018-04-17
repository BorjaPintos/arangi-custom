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
package es.accv.arangi.util;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;

import es.accv.arangi.base.certificate.validation.CAList;
import es.accv.arangi.base.exception.certificate.CertificateCANotFoundException;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.certificate.ValidationXMLException;
import es.accv.arangi.base.util.Util;
import es.accv.arangi.exception.ResourceNotLoadedException;

/**
 * Utilidades para Arangi.<br>
 * Los métodos que implican leer recursos del classpath (certificados o ficheros) buscan
 * dichos recursos en el paquete es.accv.arangi.resource.user. Si en este paquete no 
 * encuentran o no pueden cargar el recurso, entonces lo buscarán en es.accv.arangi.resource.arangi
 * donde se sitúan los recursos por defecto de la API.
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class ArangiUtil {

	static Logger logger = Logger.getLogger(ArangiUtil.class);
	
	/*
	 * Formateador de fechas simples en español
	 */
	public static final SimpleDateFormat SIMPLE_DATE_FORMAT = new SimpleDateFormat("dd-MM-yyyy");
	
	/*
	 * Primer lugar donde se buscarán los ficheros. Este lugar no existe en la librería
	 * y está hecho para que los usuarios puedan desplegar sus propios ficheros.
	 */
	private static final String PRIMARY_FILES_REPOSITORY_PACKAGE	= "es/accv/arangi/resource/user";
	
	/*
	 * Segundo lugar donde se buscarán los ficheros. Pertenece a la librería y sería el
	 * lugar por defecto.
	 */
	private static final String SECONDARY_FILES_REPOSITORY_PACKAGE	= "es/accv/arangi/resource/arangi";
	
	/*
	 * Tabla que contiene los certificados descargados
	 */
	private static HashMap hmCACertificates = new HashMap();
	
	/*
	 * Tabla que contiene los ficheros descargados
	 */
	private static HashMap hmFiles = new HashMap();
	
	/**
	 * Obtiene uno de los certificados de la CA que se encuentran dentro del classpath.
	 * 
	 * @param name Nombre del certificado
	 * @return Certificado
	 * @throws Exception 
	 */
	public static X509Certificate loadCertificate (String name) throws CertificateCANotFoundException {
		
		logger.debug ("[ArangiUtil.loadCertificate]::Obteniendo el certificado para '" + name + "'");
		
		if (hmCACertificates.containsKey(name)) {
			return (X509Certificate)hmCACertificates.get(name);
		}
		
	    try {
	    	//-- Probamos en el primer lugar
	    	String file = PRIMARY_FILES_REPOSITORY_PACKAGE + "/" + name + ".cer";
	    	InputStream is = new ArangiUtil().getClass().getClassLoader().getResourceAsStream(file);
			X509Certificate certificate = Util.getCertificate(is);
			hmCACertificates.put(name, certificate);
			return certificate;
		} catch (Exception e) {
			//-- Probamos en el segundo lugar
			try {
		    	String file = SECONDARY_FILES_REPOSITORY_PACKAGE + "/" + name + ".cer";
		    	InputStream is = new ArangiUtil().getClass().getClassLoader().getResourceAsStream(file);
				X509Certificate certificate = Util.getCertificate(is);
				hmCACertificates.put(name, certificate);
				return certificate;
			} catch (Exception e2) {
				logger.info ("[ArangiUtil.loadCertificate]::No se encuentra el certificado '" + name + "'", e2);
				throw new CertificateCANotFoundException ("No se encuentra el certificado '" + name + "'", e2);
			}
		}

	}

	/**
	 * Obtiene ficheros que se encuentran dentro del classpath.
	 * 
	 * @param fileName Nombre del fichero
	 * @return File Fichero
	 * @throws ResourceNotLoadedException No se encuentra el fichero o no se puede cargar
	 */
	public static byte[] loadFile(String fileName) throws ResourceNotLoadedException {
		logger.debug ("[ArangiUtil.loadFile]::Obteniendo el fichero '" + fileName + "'");
		
		if (hmFiles.containsKey(fileName)) {
			return (byte[])hmFiles.get(fileName);
		}
		
	    try {
	    	//-- Probamos en el primer lugar
	    	String file = PRIMARY_FILES_REPOSITORY_PACKAGE + "/" + fileName;
	    	InputStream is = new ArangiUtil().getClass().getClassLoader().getResourceAsStream(file);
	    	byte[] contenido = Util.readStream(is);
			hmFiles.put(fileName, contenido);
			return contenido;
		} catch (Exception e) {
			//-- Probamos en el segundo lugar
			try {
		    	String file = SECONDARY_FILES_REPOSITORY_PACKAGE + "/" + fileName;
		    	InputStream is = new ArangiUtil().getClass().getClassLoader().getResourceAsStream(file);
		    	byte[] contenido = Util.readStream(is);
				hmFiles.put(fileName, contenido);
				return contenido;
			} catch (Exception e2) {
				logger.info ("[ArangiUtil.loadFile]::No se encuentra el fichero '" + fileName + "'", e2);
				throw new ResourceNotLoadedException ("No se encuentra el fichero '" + fileName + "'", e2);
			}
		}
	}

	/**
	 * Obtiene la lista de certificados de CA que contiene todos los certificados
	 * de las CAs de la ACCV, tanto las de explotación como las de test. Además
	 * incluye un fichero de validación XML que incluye las URLs del OCSP de test
	 * que no se encuentran dentro de los certificados de test.
	 * 
	 * @return CAList de la ACCV
	 */
	public static CAList getACCVCaList () {
		
		logger.debug ("[ArangiUtil.getACCVCaList]::Entrada");
		
		List lCACertificates = new ArrayList ();
		try {
			//-- CA Baltimore
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/CAGVA"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/TEST_CATEST"));
			
			//-- CA Antigua
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ROOT_CA"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCV-CA1"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCV-CA2"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/TEST_ROOT_EJBCA"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/TEST_SUBCA_WINDOWS3"));
			
			//-- CA Nueva
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCVRAIZ1"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCV-CA110-SHA1"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCV-CA110-SHA256"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCV-CA120-SHA1"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCV-CA120-SHA256"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCV-CA130-SHA1"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCV-CA130-SHA256"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ROOTEJB4TEST"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCVCATEST110"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCVCATEST120"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACCVCATEST130"));
			
			//-- DNIe
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACRAIZ-SHA2"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACDNIE001-SHA2"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACDNIE002-SHA2"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACDNIE003-SHA2"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACDNIE004-SHA2"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACDNIE005-SHA2"));
			lCACertificates.add(ArangiUtil.loadCertificate("certificate/ACDNIE006-SHA2"));
			
		} catch (CertificateCANotFoundException e) {
			logger.info("[ArangiUtil.getACCVCaList]::No se encuentra alguno de los certificados de la ACCV", e);
		}

		try {
			CAList caList = new CAList (lCACertificates);
			caList.setValidationXML(ArangiUtil.loadFile("file/validation_data_accv.xml"));
			return caList;
		} catch (NormalizeCertificateException e) {
			logger.info("[ArangiUtil.getACCVCaList]::Alguno de los certificados de la ACCV no está normalizado", e);
			return null;
		} catch (ValidationXMLException e) {
			logger.info("[ArangiUtil.getACCVCaList]::El fichero validation.xml no tiene el formato correcto", e);
			return null;
		} catch (ResourceNotLoadedException e) {
			logger.info("[ArangiUtil.getACCVCaList]::No se encuentra el fichero validation.xml", e);
			return null;
		}
	}
}
