/*
 * 17-abr-2018 - File: - KeyStoreManager.java
 * Author: Borja Pintos Castro - borjapintoscastro@gmail.com
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
 * The Class KeyStoreManager.
 */
public class KeyStoreManager extends es.accv.arangi.base.device.KeyStoreManager implements ACCVDeviceManager {

	/** The logger. */
	/*
	 * Logger de la clase
	 */
	static Logger logger = Logger.getLogger(KeyStoreManager.class);
	
	/** The custom aliases. */
	private CustomAliases customAliases = null;

	/**
	 * Instantiates a new key store manager.
	 *
	 * @param ksFile the ks file
	 * @param pin the pin
	 * @throws DeviceNotFoundException the device not found exception
	 * @throws ClosingStreamException the closing stream exception
	 * @throws OpeningDeviceException the opening device exception
	 * @throws IncorrectPINException the incorrect PIN exception
	 */
	public KeyStoreManager(File ksFile, String pin) throws DeviceNotFoundException, ClosingStreamException, OpeningDeviceException, IncorrectPINException {
		super(ksFile, pin);
	}
	
	/**
	 * Instantiates a new key store manager.
	 *
	 * @param ksFile the ks file
	 * @param pin the pin
	 * @param customAliases the custom aliases
	 * @throws DeviceNotFoundException the device not found exception
	 * @throws ClosingStreamException the closing stream exception
	 * @throws OpeningDeviceException the opening device exception
	 * @throws IncorrectPINException the incorrect PIN exception
	 */
	public KeyStoreManager(File ksFile, String pin, CustomAliases customAliases) throws DeviceNotFoundException, ClosingStreamException, OpeningDeviceException, IncorrectPINException {
		this(ksFile, pin);
		this.customAliases = customAliases;
	}

	/**
	 * Instantiates a new key store manager.
	 *
	 * @param is the is
	 * @param pin the pin
	 * @throws DeviceNotFoundException the device not found exception
	 * @throws ReadingStreamException the reading stream exception
	 * @throws OpeningDeviceException the opening device exception
	 * @throws IncorrectPINException the incorrect PIN exception
	 */
	public KeyStoreManager(InputStream is, String pin) throws DeviceNotFoundException, ReadingStreamException, OpeningDeviceException, IncorrectPINException {
		super(is, pin);
	}
	
	/**
	 * Instantiates a new key store manager.
	 *
	 * @param is the is
	 * @param pin the pin
	 * @param customAliases the custom aliases
	 * @throws DeviceNotFoundException the device not found exception
	 * @throws ReadingStreamException the reading stream exception
	 * @throws OpeningDeviceException the opening device exception
	 * @throws IncorrectPINException the incorrect PIN exception
	 */
	public KeyStoreManager(InputStream is, String pin, CustomAliases customAliases) throws DeviceNotFoundException, ReadingStreamException, OpeningDeviceException, IncorrectPINException {
		this(is, pin);
		this.customAliases = customAliases;
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
			// Esta excepci�n no se puede dar
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
			// Esta excepci�n no se puede dar
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
			// Esta excepci�n no se puede dar
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
			logger.info("[KeyStoremanager.getSignatureAlias]::El dispositivo est� vac�o");
			throw new LoadingObjectException ("El dispositivo est� vac�o");
		}
		
		List<String> lAlias = Arrays.asList(aliases);
		if (lAlias.contains(CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA)) {
			logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de firma para certificado de ciudadano");
			return CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA;
		}
		if (lAlias.contains(CertificadoEmpleadoPublico.ALIAS_PKCS11)) {
			logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de firma para empleado p�blico");
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
		if (customAliases != null && customAliases.getSignatureAlias() != null){
			if (lAlias.contains(customAliases.getSignatureAlias())){
				logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de firma para customAlias");
				return customAliases.getSignatureAlias();
			}
		}
		
		logger.debug ("[KeyStoremanager.getSignatureAlias]::No se ha encontrado ning�n alias conocido. Se devuelve el primero::" + aliases[0]);
		return aliases[0];
	}

	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getCipherAlias()
	 */
	public String getCipherAlias () throws LoadingObjectException {
		
		String[] aliases = getAliasNamesList();
		if (aliases == null || aliases.length == 0) {
			logger.info("[KeyStoremanager.getCipherAlias]::El dispositivo est� vac�o");
			throw new LoadingObjectException ("El dispositivo est� vac�o");
		}
		
		List<String> lAlias = Arrays.asList(aliases);
		if (lAlias.contains(CertificadoCiudadano.ALIAS_KEYSTORE_CIFRADO)) {
			logger.debug ("[KeyStoremanager.getCipherAlias]::Encontrado alias de cifrado para certificado de ciudadano");
			return CertificadoCiudadano.ALIAS_KEYSTORE_CIFRADO;
		}
		if (lAlias.contains(CertificadoEmpleadoPublico.ALIAS_PKCS11)) {
			logger.debug ("[KeyStoremanager.getCipherAlias]::Encontrado alias de cifrado para empleado p�blico");
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
		if (customAliases != null && customAliases.getCipherAlias() != null){
			if (lAlias.contains(customAliases.getCipherAlias())){
				logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de cifrado para customAlias");
				return customAliases.getCipherAlias();
			}
		}
		
		logger.debug ("[KeyStoremanager.getCipherAlias]::No se ha encontrado ning�n alias conocido. Se devuelve el primero::" + aliases[0]);
		return aliases[0];
	}
	
	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getAuthenticationAlias()
	 */
	public String getAuthenticationAlias () throws LoadingObjectException {
		
		String[] aliases = getAliasNamesList();
		if (aliases == null || aliases.length == 0) {
			logger.info("[KeyStoremanager.getAuthenticationAlias]::El dispositivo est� vac�o");
			throw new LoadingObjectException ("El dispositivo est� vac�o");
		}
		
		List<String> lAlias = Arrays.asList(aliases);
		if (lAlias.contains(CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA)) {
			logger.debug ("[KeyStoremanager.getAuthenticationAlias]::Encontrado alias de autenticaci�n para certificado de ciudadano");
			return CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA;
		}
		if (lAlias.contains(CertificadoEmpleadoPublico.ALIAS_PKCS11)) {
			logger.debug ("[KeyStoremanager.getAuthenticationAlias]::Encontrado alias de autenticaci�n para empleado p�blico");
			return CertificadoEmpleadoPublico.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoEntidad.ALIAS_PKCS11)) {
			logger.debug ("[KeyStoremanager.getAuthenticationAlias]::Encontrado alias de autenticaci�n para entidades");
			return CertificadoEntidad.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoDNIe.ALIAS_PKCS11_AUTENTICACION)) {
			logger.debug ("[KeyStoremanager.getAuthenticationAlias]::Encontrado alias de autenticaci�n para DNIe");
			return CertificadoDNIe.ALIAS_PKCS11_AUTENTICACION;
		}
		if (customAliases != null && customAliases.getAuthenticationAlias() != null){
			if (lAlias.contains(customAliases.getAuthenticationAlias())){
				logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de autenticaci�n para customAlias");
				return customAliases.getAuthenticationAlias();
			}
		}
		
		logger.debug ("[KeyStoremanager.getAuthenticationAlias]::No se ha encontrado ning�n alias conocido. Se devuelve el primero::" + aliases[0]);
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
	 * Gets the empty key store.
	 *
	 * @param storeType the store type
	 * @param pin the pin
	 * @return the empty key store
	 * @throws OpeningDeviceException the opening device exception
	 */
	public static KeyStoreManager getEmptyKeyStore(String storeType, String pin)throws OpeningDeviceException {

		logger.info("[KeyStoreManager.getEmptyKeyStore]::Entrada::" + Arrays.asList (new Object[] { storeType }));
		
		//-- Utilizar el m�todo de la clase base para generar un keystore 
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

	//-- M�todos privados
	
	
}
