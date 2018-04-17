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
package es.accv.arangi.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
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
 * Los m�todos que implican leer recursos del classpath (certificados o ficheros) buscan
 * dichos recursos en el paquete es.accv.arangi.resource.user. Si en este paquete no 
 * encuentran o no pueden cargar el recurso, entonces lo buscar�n en es.accv.arangi.resource.arangi
 * donde se sit�an los recursos por defecto de la API.
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class ArangiUtil {

	static Logger logger = Logger.getLogger(ArangiUtil.class);
	
	/*
	 * Formateador de fechas simples en espa�ol
	 */
	public static final SimpleDateFormat SIMPLE_DATE_FORMAT = new SimpleDateFormat("dd-MM-yyyy");
	
	/*
	 * Primer lugar donde se buscar�n los ficheros. Este lugar no existe en la librer�a
	 * y est� hecho para que los usuarios puedan desplegar sus propios ficheros.
	 */
	private static final String PRIMARY_FILES_REPOSITORY_PACKAGE	= "es/accv/arangi/resource/user";
	
	/*
	 * Segundo lugar donde se buscar�n los ficheros. Pertenece a la librer�a y ser�a el
	 * lugar por defecto.
	 */
	private static final String SECONDARY_FILES_REPOSITORY_PACKAGE	= "es/accv/arangi/resource/arangi";
	
	/*
	 * Tabla que contiene los certificados descargados
	 */
	private static HashMap<String, X509Certificate> hmCACertificates = new HashMap<String, X509Certificate>();
	
	/*
	 * Tabla que contiene los ficheros descargados
	 */
	private static HashMap<String, byte[]> hmFiles = new HashMap<String, byte[]>();
	
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
			return hmCACertificates.get(name);
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
	 * Obtiene uno de los certificados de la CA que se encuentran en un fichero.
	 * 
	 * @param name Nombre del certificado
	 * @return Certificado
	 * @throws Exception 
	 */
	public static X509Certificate loadCertificate (String name, String folderPath) throws CertificateCANotFoundException {
		
		logger.debug ("[ArangiUtil.loadCertificate]::Obteniendo el certificado para '" + name + "'");
		
		if (hmCACertificates.containsKey(name)) {
			return hmCACertificates.get(name);
		}
		
		//-- Probamos en el segundo lugar
		try {
	    	String file = folderPath + "/" + name + ".cer";
	    	InputStream is = new FileInputStream(new File(file));
			X509Certificate certificate = Util.getCertificate(is);
			hmCACertificates.put(name, certificate);
			return certificate;
		} catch (Exception e2) {
			logger.info ("[ArangiUtil.loadCertificate]::No se encuentra el certificado '" + name + "'", e2);
			throw new CertificateCANotFoundException ("No se encuentra el certificado '" + name + "'", e2);
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
			return hmFiles.get(fileName);
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
	 * de las CAs de la ACCV, tanto las de explotaci�n como las de test. Adem�s
	 * incluye un fichero de validaci�n XML que incluye las URLs del OCSP de test
	 * que no se encuentran dentro de los certificados de test.
	 * 
	 * @return CAList de la ACCV
	 */
	public static CAList getACCVCaList () {
		
		logger.debug ("[ArangiUtil.getACCVCaList]::Entrada");
		
		List<X509Certificate> lCACertificates = BBDDCerts.getInstance().getCertificatesCA();

		try {
			CAList caList = new CAList (lCACertificates);
			caList.setValidationXML(ArangiUtil.loadFile("file/validation_data_accv.xml"));
			return caList;
		} catch (NormalizeCertificateException e) {
			logger.info("[ArangiUtil.getACCVCaList]::Alguno de los certificados de la ACCV no est� normalizado", e);
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
