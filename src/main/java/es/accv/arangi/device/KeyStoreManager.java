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
package es.accv.arangi.device;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.apache.log4j.Logger;

import es.accv.arangi.base.algorithm.DigitalSignatureAlgorithm;
import es.accv.arangi.base.document.IDocument;
import es.accv.arangi.base.exception.device.AliasNotFoundException;
import es.accv.arangi.base.exception.device.CipherException;
import es.accv.arangi.base.exception.device.ClosingStreamException;
import es.accv.arangi.base.exception.device.DeviceNotFoundException;
import es.accv.arangi.base.exception.device.IncorrectPINException;
import es.accv.arangi.base.exception.device.LoadingObjectException;
import es.accv.arangi.base.exception.device.OpeningDeviceException;
import es.accv.arangi.base.exception.device.ReadingStreamException;
import es.accv.arangi.base.exception.device.SaveDeviceException;
import es.accv.arangi.base.exception.document.HashingException;
import es.accv.arangi.base.exception.signature.SignatureException;
import es.accv.arangi.certificate.CertificadoCiudadano;
import es.accv.arangi.certificate.CertificadoDNIe;
import es.accv.arangi.certificate.CertificadoEmpleadoPublico;
import es.accv.arangi.certificate.CertificadoEntidad;

/**
 * Clase para el manejo de keystores de la ACCV (Ficheros PKCS#12 que se entregan
 * a los ciudadanos).<br><br>
 * 
 * Ejemplo de uso:<br><br>
 * 
 * <code>
 *  IDocument document = new FileDocument(new File ("/documento.txt"));<br>
 * 	KeyStoreManager manager = new KeyStoreManager (new File ("/keystores/ks.pk12"), "1234");<br>
 *  System.out.println ("Certificate: " + manager.getCertificate());<br>
 * 	System.out.println ("Firma: " + manager.signDocument(document));
 * </code>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class KeyStoreManager extends es.accv.arangi.base.device.KeyStoreManager implements ACCVDeviceManager {

	/*
	 * Logger de la clase
	 */
	static Logger logger = Logger.getLogger(KeyStoreManager.class);

	/**
 	 * Inicializa un gestor de KeyStore con el fichero pasado como parámetro.
 	 * 
	 * @param ksFile Fichero del Keystore (PKCS#12 o JKS)
	 * @param pin PIN del dispositivo
	 * @throws DeviceNotFoundException El fichero no existe
	 * @throws ClosingStreamException No se ha podido cerrar correctamente el stream de lectura
	 *  del fichero
	 * @throws OpeningDeviceException Error no controlado abriendo el dispositivo
	 * @throws IncorrectPINException El PIN proporcionado para abrir el dispositivo no es correcto
	 */
	public KeyStoreManager(File ksFile, String pin) throws DeviceNotFoundException, ClosingStreamException, OpeningDeviceException, IncorrectPINException {
		super(ksFile, pin);
	}

	/**
 	 * Inicializa un gestor de KeyStores mediante un stream al fichero
 	 * 
	 * @param is Stream de lectura al fichero del Keystore (PKCS#12 o JKS)
	 * @param pin PIN del dispositivo
	 * @throws DeviceNotFoundException El stream de lectura pasado como parámetro es nulo
	 * @throws ReadingStreamException Error leyendo el stream de lectura
	 * @throws OpeningDeviceException Error no controlado abriendo el dispositivo
	 * @throws IncorrectPINException El PIN proporcionado para abrir el dispositivo no es correcto
	 */
	public KeyStoreManager(InputStream is, String pin) throws DeviceNotFoundException, ReadingStreamException, OpeningDeviceException, IncorrectPINException {
		super(is, pin);
	}

	
	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#signDocument(es.accv.arangi.base.document.IDocument)
	 */
	public byte[] signDocument(IDocument document) throws HashingException, LoadingObjectException, SignatureException {
		
		logger.debug ("[Pkcs11Manager.signDocument]::Entrada::" + document);
		
		//-- Firmar
		try {
			return signDocument(document, getSignatureAlias(), DigitalSignatureAlgorithm.SHA1_RSA);
		} catch (AliasNotFoundException e) {
			// Esta excepción no se puede dar
			logger.info("[Pkcs11Manager.signDocument]::No se puede obtener la clave de firma");
			throw new LoadingObjectException ("No se puede obtener la clave de firma");
		}
	}

	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#signDocument(java.io.InputStream)
	 */
	public byte[] signDocument(InputStream document) throws AliasNotFoundException, HashingException, LoadingObjectException, SignatureException {
		logger.debug ("[Pkcs11Manager.signDocument]::Entrada::" + document);
		
		//-- Firmar
		try {
			return signDocument(document, getSignatureAlias(), DigitalSignatureAlgorithm.SHA1_RSA);
		} catch (AliasNotFoundException e) {
			// Esta excepción no se puede dar
			logger.info("[Pkcs11Manager.signDocument]::No se puede obtener la clave de firma");
			throw new LoadingObjectException ("No se puede obtener la clave de firma");
		}
	}

	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#signHash(byte[])
	 */
	public byte[] signBytesHash(byte[] hash) throws HashingException, AliasNotFoundException, LoadingObjectException, CipherException {
		logger.debug ("[Pkcs11Manager.signHash]::Entrada::" + hash);
		
		//-- Firmar
		try {
			return signBytesHash(hash, getSignatureAlias());
		} catch (AliasNotFoundException e) {
			// Esta excepción no se puede dar
			logger.info("[Pkcs11Manager.signHash]::No se puede obtener la clave de firma");
			throw new LoadingObjectException ("No se puede obtener la clave de firma");
		}
	}
	
	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getSignatureAlias()
	 */
	public String getSignatureAlias () throws LoadingObjectException {
		
		String[] aliases = getAliasNamesList();
		if (aliases == null || aliases.length == 0) {
			logger.info("[KeyStoremanager.getSignatureAlias]::El dispositivo está vacío");
			throw new LoadingObjectException ("El dispositivo está vacío");
		}
		
		List lAlias = Arrays.asList(aliases);
		if (lAlias.contains(CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA)) {
			logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de firma para certificado de ciudadano");
			return CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA;
		}
		if (lAlias.contains(CertificadoEmpleadoPublico.ALIAS_PKCS11)) {
			logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de firma para empleado público");
			return CertificadoEmpleadoPublico.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoEntidad.ALIAS_PKCS11)) {
			logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de firma para entidades");
			return CertificadoEntidad.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoDNIe.ALIAS_PKCS11_FIRMA)) {
			logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de firma para DNIe");
			return CertificadoDNIe.ALIAS_PKCS11_FIRMA;
		}
		
		logger.debug ("[KeyStoremanager.getSignatureAlias]::No se ha encontrado ningún alias conocido. Se devuelve el primero::" + aliases[0]);
		return aliases[0];
	}

	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getCipherAlias()
	 */
	public String getCipherAlias () throws LoadingObjectException {
		
		String[] aliases = getAliasNamesList();
		if (aliases == null || aliases.length == 0) {
			logger.info("[KeyStoremanager.getCipherAlias]::El dispositivo está vacío");
			throw new LoadingObjectException ("El dispositivo está vacío");
		}
		
		List lAlias = Arrays.asList(aliases);
		if (lAlias.contains(CertificadoCiudadano.ALIAS_KEYSTORE_CIFRADO)) {
			logger.debug ("[KeyStoremanager.getCipherAlias]::Encontrado alias de cifrado para certificado de ciudadano");
			return CertificadoCiudadano.ALIAS_KEYSTORE_CIFRADO;
		}
		if (lAlias.contains(CertificadoEmpleadoPublico.ALIAS_PKCS11)) {
			logger.debug ("[KeyStoremanager.getCipherAlias]::Encontrado alias de cifrado para empleado público");
			return CertificadoEmpleadoPublico.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoEntidad.ALIAS_PKCS11)) {
			logger.debug ("[KeyStoremanager.getCipherAlias]::Encontrado alias de cifrado para entidades");
			return CertificadoEntidad.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoDNIe.ALIAS_PKCS11_FIRMA)) {
			logger.debug ("[KeyStoremanager.getCipherAlias]::Encontrado alias de cifrado para DNIe");
			return CertificadoDNIe.ALIAS_PKCS11_FIRMA;
		}
		
		logger.debug ("[KeyStoremanager.getCipherAlias]::No se ha encontrado ningún alias conocido. Se devuelve el primero::" + aliases[0]);
		return aliases[0];
	}
	
	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getAuthenticationAlias()
	 */
	public String getAuthenticationAlias () throws LoadingObjectException {
		
		String[] aliases = getAliasNamesList();
		if (aliases == null || aliases.length == 0) {
			logger.info("[KeyStoremanager.getAuthenticationAlias]::El dispositivo está vacío");
			throw new LoadingObjectException ("El dispositivo está vacío");
		}
		
		List lAlias = Arrays.asList(aliases);
		if (lAlias.contains(CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA)) {
			logger.debug ("[KeyStoremanager.getAuthenticationAlias]::Encontrado alias de autenticación para certificado de ciudadano");
			return CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA;
		}
		if (lAlias.contains(CertificadoEmpleadoPublico.ALIAS_PKCS11)) {
			logger.debug ("[KeyStoremanager.getAuthenticationAlias]::Encontrado alias de autenticación para empleado público");
			return CertificadoEmpleadoPublico.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoEntidad.ALIAS_PKCS11)) {
			logger.debug ("[KeyStoremanager.getAuthenticationAlias]::Encontrado alias de autenticación para entidades");
			return CertificadoEntidad.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoDNIe.ALIAS_PKCS11_AUTENTICACION)) {
			logger.debug ("[KeyStoremanager.getAuthenticationAlias]::Encontrado alias de autenticación para DNIe");
			return CertificadoDNIe.ALIAS_PKCS11_AUTENTICACION;
		}
		
		logger.debug ("[KeyStoremanager.getAuthenticationAlias]::No se ha encontrado ningún alias conocido. Se devuelve el primero::" + aliases[0]);
		return aliases[0];
	}

	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getSignatureCertificate()
	 */
	public X509Certificate getSignatureCertificate () throws LoadingObjectException {
		return getCertificate(getSignatureAlias());
	}
		
	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getCipherCertificate()
	 */
	public X509Certificate getCipherCertificate () throws LoadingObjectException {
		return getCertificate(getCipherAlias());
	}
		
	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getAuthenticationCertificate()
	 */
	public X509Certificate getAuthenticationCertificate () throws LoadingObjectException {
		return getCertificate(getAuthenticationAlias());
	}
		
	/**
	   * Crea un fichero PKCS#12 vacío
	   * 
	   * @param storeType Tipo de keystore (STORE_TYPE_JKS o STORE_TYPE_PKCS12 de la clase KeyStoreManager de Arangí Base)
	   * @param pin Contraseña del keystore
	   * @return Manager al keystore recien creado
	   * @throws OpeningDeviceException Excepciones creando y serializando el keystore
	   */
	public static KeyStoreManager getEmptyKeyStore(String storeType, String pin)throws OpeningDeviceException {

		logger.info("[KeyStoreManager.getEmptyKeyStore]::Entrada::" + Arrays.asList (new Object[] { storeType }));
		
		//-- Utilizar el método de la clase base para generar un keystore 
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			es.accv.arangi.base.device.KeyStoreManager.getEmptyKeyStore(storeType, pin).save(baos);
		} catch (SaveDeviceException e) {
			logger.info("[KeyStoreManager.getEmptyKeyStore]:: No ha sido posible serializar el keystore de tipo '" + storeType + "'", e);
			throw new OpeningDeviceException("No ha sido posible serializar el keystore de tipo '" + storeType + "'", e);
		}
		
		try {
			return new KeyStoreManager (new ByteArrayInputStream(baos.toByteArray()), pin);
		} catch (Exception e) {
			logger.info("[KeyStoreManager.getEmptyKeyStore]:: No ha sido posible crear un keystore de tipo '" + storeType + "'", e);
			throw new OpeningDeviceException("No ha sido posible crear un keystore de tipo '" + storeType + "'", e);
		} 
	}

	//-- Métodos privados
	
	
}
