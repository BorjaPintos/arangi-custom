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
package es.accv.arangi.device;

import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.log4j.Logger;

import es.accv.arangi.base.algorithm.DigitalSignatureAlgorithm;
import es.accv.arangi.base.device.model.Pkcs11Device;
import es.accv.arangi.base.device.model.Pkcs11Manufacturer;
import es.accv.arangi.base.document.IDocument;
import es.accv.arangi.base.exception.device.AliasNotFoundException;
import es.accv.arangi.base.exception.device.CipherException;
import es.accv.arangi.base.exception.device.DeviceNotFoundException;
import es.accv.arangi.base.exception.device.IAIKDLLNotFoundException;
import es.accv.arangi.base.exception.device.IncorrectPINException;
import es.accv.arangi.base.exception.device.IncorrectPUKException;
import es.accv.arangi.base.exception.device.InitializeProviderException;
import es.accv.arangi.base.exception.device.LoadingObjectException;
import es.accv.arangi.base.exception.device.LockedPINException;
import es.accv.arangi.base.exception.device.ModuleNotFoundException;
import es.accv.arangi.base.exception.device.NoSuitableDriversException;
import es.accv.arangi.base.exception.device.OpeningDeviceException;
import es.accv.arangi.base.exception.device.SearchingException;
import es.accv.arangi.base.exception.document.HashingException;
import es.accv.arangi.base.exception.signature.SignatureException;
import es.accv.arangi.certificate.CertificadoCiudadano;
import es.accv.arangi.certificate.CertificadoDNIe;
import es.accv.arangi.certificate.CertificadoEmpleadoPublico;
import es.accv.arangi.certificate.CertificadoEntidad;
import es.accv.arangi.certificate.CertificadoPertenenciaEmpresa;
import es.accv.arangi.certificate.CertificadoRepresentante;
import es.accv.arangi.certificate.CertificadoSeudonimo;
import es.accv.arangi.device.model.Pkcs11DNIeManufacturer;
import es.accv.arangi.device.model.Pkcs11GYDManufacturer;
import es.accv.arangi.device.model.Pkcs11GemaltoManufacturer;
import es.accv.arangi.device.model.Pkcs11GemaltoR7Manufacturer;
import es.accv.arangi.device.model.Pkcs11SiemensManufacturer;
import es.accv.arangi.device.model.Pkcs11TYSManufacturer;

/**
 * Clase de manejo de dispositivos PKCS#11 (tarjetas inteligentes) usados 
 * por la ACCV.
 * 
 * En los casos en que Arangi se encargue de buscar los m�dulos con los que
 * trabajan las tarjetas, �sta es la lista de m�dulos que buscar�:
 * <ul>
 * 	<li><i>aetpkss1</i>: m�dulo para tarjetas GyD</li>
 * 	<li><i>CardOS_PKCS11</i>: m�dulo para tarjetas Siemens antiguas</li>
 * 	<li><i>siecap11</i>: m�dulo para tarjetas Siemene nuevas</li>
 * 	<li><i>AdvantisPKCS11</i>: m�dulo para tarjetas Sermepa</li>
 * </ul><br>
 * 
 * Ejemplo de uso:<br><br>
 * 
 * <code>
 *  IDocument document = new FileDocument(new File ("/documento.txt"));<br>
 * 	Pkcs11Manager manager = new Pkcs11Manager ("accv1234");<br>
 * 	System.out.println ("Firma: " + manager.signDocument(document)); // Obtener los bytes de la firma
 * </code>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class Pkcs11Manager extends es.accv.arangi.base.device.Pkcs11Manager implements ACCVDeviceManager {

	/*
	 * Logger de la clase
	 */
	Logger logger = Logger.getLogger(Pkcs11Manager.class);
	
	private CustomAliases customAliases = null;
	
	//-- Constructores

	/**
	 * Inicializa un gestor de PKCS#11 realizando previamente un proceso de 
	 * autodetecci�n de la tarjeta insertada el lector de acuerdo a los m�dulos
	 * tratados por Arangi. En caso de que hayan varios dispositivos conectados 
	 * se elegir� el primero de ellos, por lo que este m�todo est� recomendado
	 * para usarlo en el caso m�s habitual: que s�lo exista un dispositivo 
	 * PKCS#11 conectado.
	 * 
	 * @param pin PIN para abrir el dispositivo
	 * @throws ModuleNotFoundException No se ha encontrado ning�n m�dulo PKCS#11
	 * 	de la lista de los utilizados por la ACCV instalado en el equipo.
	 * @throws IncorrectPINException El PIN no es correcto
	 * @throws LockedPINException El PIN est� bloqueado
	 * @throws OpeningDeviceException Error durante el proceso de apertura
	 * @throws IAIKDLLNotFoundException No es posible cargar la DLL de IAIK, por 
	 * 	lo que no se puede trabajar con dispositivos PKCS#11
	 * @throws InitializeProviderException No es posible inicializar el proveedor PKCS#11 de Sun
	 */
	public Pkcs11Manager(String pin) throws ModuleNotFoundException, IncorrectPINException, LockedPINException, OpeningDeviceException, IAIKDLLNotFoundException, InitializeProviderException {
		super(pin, getManufacturers());
	}
	
	/**
	 *  Lo mismo que el metodo Pkcs11Manager(String pin), pero pasandole customAliases
	 */
	public Pkcs11Manager(String pin, CustomAliases customAliases) throws ModuleNotFoundException, IncorrectPINException, LockedPINException, OpeningDeviceException, IAIKDLLNotFoundException, InitializeProviderException {
		this(pin);
		this.customAliases = customAliases;
	}

	/**
	 * Inicializa un gestor de PKCS#11 realizando previamente un proceso de 
	 * autodetecci�n de la tarjeta insertada el lector de acuerdo a los m�dulos
	 * tratados por Arangi. En caso de que hayan varios dispositivos conectados 
	 * se elegir� el primero de ellos, por lo que este m�todo est� recomendado
	 * para usarlo en el caso m�s habitual: que s�lo exista un dispositivo 
	 * PKCS#11 conectado.
	 * 
	 * @param password PIN o PUK para abrir el dispositivo
	 * @param isPUK Determina si el primer par�metro es el PIN o el PUK
	 * @param withKeystore Indica si se quiere cargar el keystore interno de firma.
	 * 	Si se va a utilizar el manager para actualizar el contenido o modificar el
	 *  PIN o el PUK es m�s optimo marcar este par�metro a falso.
	 * @throws ModuleNotFoundException No se ha encontrado ning�n m�dulo PKCS#11
	 * 	de la lista de los utilizados por la ACCV instalado en el equipo.
	 * @throws IncorrectPINException El PIN no es correcto
	 * @throws LockedPINException El PIN est� bloqueado
	 * @throws OpeningDeviceException Error durante el proceso de apertura
	 * @throws IAIKDLLNotFoundException No es posible cargar la DLL de IAIK, por 
	 * 	lo que no se puede trabajar con dispositivos PKCS#11
	 * @throws InitializeProviderException No es posible inicializar el proveedor PKCS#11 de Sun
	 * @throws IncorrectPUKException El PUK no es correcto
	 */
	public Pkcs11Manager(String password, boolean isPUK, boolean withKeystore) throws ModuleNotFoundException, IncorrectPINException, LockedPINException, OpeningDeviceException, IAIKDLLNotFoundException, InitializeProviderException, IncorrectPUKException {
		super(password, isPUK, getManufacturers(), withKeystore);
	}
	
	/**
	 *  Lo mismo que el metodo Pkcs11Manager(String password, boolean isPUK, boolean withKeystore), pero pasandole customAliases
	 */
	public Pkcs11Manager(String password, boolean isPUK, boolean withKeystore, CustomAliases customAliases) throws ModuleNotFoundException, IncorrectPINException, LockedPINException, OpeningDeviceException, IAIKDLLNotFoundException, InitializeProviderException, IncorrectPUKException {
		this(password, isPUK, withKeystore);
		this.customAliases = customAliases;
	}

	/**
	 * Inicializa un gestor de PKCS#11 realizando previamente un proceso de 
	 * autodetecci�n de la tarjeta insertada el lector de acuerdo a los m�dulos
	 * tratados por Arangi. En caso de que hayan varios dispositivos conectados 
	 * se elegir� el primero de ellos, por lo que este m�todo est� recomendado
	 * para usarlo en el caso m�s habitual: que s�lo exista un dispositivo 
	 * PKCS#11 conectado.
	 * 
	 * @param password PIN o PUK para abrir el dispositivo
	 * @param isPUK Determina si el primer par�metro es el PIN o el PUK
	 * @throws ModuleNotFoundException No se ha encontrado ning�n m�dulo PKCS#11
	 * 	de la lista de los utilizados por la ACCV instalado en el equipo.
	 * @throws IncorrectPINException El PIN no es correcto
	 * @throws IncorrectPUKException El PUK no es correcto
	 * @throws LockedPINException El PIN est� bloqueado
	 * @throws OpeningDeviceException Error durante el proceso de apertura
	 * @throws IAIKDLLNotFoundException No es posible cargar la DLL de IAIK, por 
	 * 	lo que no se puede trabajar con dispositivos PKCS#11
	 * @throws InitializeProviderException No es posible inicializar el proveedor PKCS#11 de Sun
	 */
	public Pkcs11Manager(String password, boolean isPUK) throws ModuleNotFoundException, IncorrectPINException,	IncorrectPUKException, LockedPINException, OpeningDeviceException, IAIKDLLNotFoundException, InitializeProviderException {
		super(password, isPUK, getManufacturers());
	}
	
	/**
	 *  Lo mismo que el metodo Pkcs11Manager(String password, boolean isPUK), pero pasandole customAliases
	 */
	public Pkcs11Manager(String password, boolean isPUK, CustomAliases customAliases) throws ModuleNotFoundException, IncorrectPINException,	IncorrectPUKException, LockedPINException, OpeningDeviceException, IAIKDLLNotFoundException, InitializeProviderException {
		this(password, isPUK);
		this.customAliases = customAliases;
	}

	/**
	 * Inicializa un gestor de PKCS#11 para el dispositivo pasado como par�metro.
	 * Dicho dispositivo puede ser obtenido tras el proceso de autodetecci�n de
	 * todos los dispositivos PKCS#11 realizado mediante el m�todo est�tico 
	 * {@link #getConnectedDevices() getConnectedDevices}. 
	 * 
	 * @param device Dispositivo elegido para este manager
	 * @param pin PIN para abrir el dispositivo
	 * 
	 * @throws ModuleNotFoundException No se ha encontrado el m�dulo PKCS#11
	 * 	adecuado instalado en el equipo.
	 * @throws IncorrectPINException El PIN no es correcto
	 * @throws LockedPINException El PIN est� bloqueado
	 * @throws OpeningDeviceException Error durante el proceso de apertura
	 * @throws DeviceNotFoundException El dispositivo no existe
	 * @throws IAIKDLLNotFoundException No es posible cargar la DLL de IAIK, por 
	 * 	lo que no se puede trabajar con dispositivos PKCS#11
	 * @throws InitializeProviderException No es posible inicializar el proveedor PKCS#11 de Sun
	 */
	public Pkcs11Manager(Pkcs11Device device, String pin) throws ModuleNotFoundException, IncorrectPINException, 
	LockedPINException, OpeningDeviceException, DeviceNotFoundException, IAIKDLLNotFoundException, InitializeProviderException {
		super(device, pin);
	}
	
	/**
	 *  Lo mismo que el metodo Pkcs11Manager(Pkcs11Device device, String pin), pero pasandole customAliases
	 */
	public Pkcs11Manager(Pkcs11Device device, String pin, CustomAliases customAliases) throws ModuleNotFoundException, IncorrectPINException, 
	LockedPINException, OpeningDeviceException, DeviceNotFoundException, IAIKDLLNotFoundException, InitializeProviderException {
		this(device, pin);
		this.customAliases = customAliases;
	}

	/**
	 * Inicializa un gestor de PKCS#11 para el dispositivo pasado como par�metro.
	 * Dicho dispositivo puede ser obtenido tras el proceso de autodetecci�n de
	 * todos los dispositivos PKCS#11 realizado mediante el m�todo est�tico 
	 * {@link #getConnectedDevices() getConnectedDevices}. <br><br>
	 * 
	 * Si el dispositivo se abre con el PUK, normalmente el siguiente paso ser�
	 * invocar al m�todo {@link #unlockPIN(String) unlockPIN}, ya que el PUK se
	 * suele usar para desbloquear el PIN de la tarjeta. Otra forma de hacer esto
	 * mismo en un s�lo paso es llamar al m�todo est�tico {@link #unlockPIN(Pkcs11Device,String,String) unlockPIN}.
	 * 
	 * @param device Dispositivo elegido para este manager
	 * @param password PIN o PUK para abrir el dispositivo
	 * @param isPUK Determina si el primer par�metro es el PIN o el PUK
	 * 
	 * @throws ModuleNotFoundException No se ha encontrado el m�dulo PKCS#11
	 * 	adecuado instalado en el equipo.
	 * @throws IncorrectPINException El PIN no es correcto
	 * @throws IncorrectPUKException El PUK no es correcto
	 * @throws LockedPINException El PIN est� bloqueado
	 * @throws OpeningDeviceException Error durante el proceso de apertura
	 * @throws DeviceNotFoundException El dispositivo no existe
	 * @throws IAIKDLLNotFoundException No es posible cargar la DLL de IAIK, por 
	 * 	lo que no se puede trabajar con dispositivos PKCS#11
	 * @throws InitializeProviderException No es posible inicializar el proveedor PKCS#11 de Sun
	 */
	public Pkcs11Manager(Pkcs11Device device, String password, boolean isPUK) throws ModuleNotFoundException, 
		IncorrectPINException, IncorrectPUKException, LockedPINException, OpeningDeviceException, DeviceNotFoundException,
		IAIKDLLNotFoundException, InitializeProviderException {
		
		super(device, password, isPUK);
	}
	
	/**
	 *  Lo mismo que el metodo Pkcs11Manager(Pkcs11Device device, String pin), pero pasandole customAliases
	 */
	public Pkcs11Manager(Pkcs11Device device, String password, boolean isPUK, CustomAliases customAliases) throws ModuleNotFoundException, 
		IncorrectPINException, IncorrectPUKException, LockedPINException, OpeningDeviceException, DeviceNotFoundException,
		IAIKDLLNotFoundException, InitializeProviderException {
		this(device, password, isPUK);
		this.customAliases = customAliases;
	}

	/**
	 * Inicializa un gestor de PKCS#11 para el dispositivo pasado como par�metro.
	 * Dicho dispositivo puede ser obtenido tras el proceso de autodetecci�n de
	 * todos los dispositivos PKCS#11 realizado mediante el m�todo est�tico 
	 * {@link #getConnectedDevices() getConnectedDevices}. <br><br>
	 * 
	 * Si el dispositivo se abre con el PUK, normalmente el siguiente paso ser�
	 * invocar al m�todo {@link #unlockPIN(String) unlockPIN}, ya que el PUK se
	 * suele usar para desbloquear el PIN de la tarjeta. Otra forma de hacer esto
	 * mismo en un s�lo paso es llamar al m�todo est�tico {@link #unlockPIN(Pkcs11Device,String,String) unlockPIN}.
	 * 
	 * @param device Dispositivo elegido para este manager
	 * @param password PIN o PUK para abrir el dispositivo
	 * @param isPUK Determina si el primer par�metro es el PIN o el PUK
	 * @param withKeystore Indica si se quiere cargar el keystore interno de firma.
	 * 	Si se va a utilizar el manager para actualizar el contenido o modificar el
	 *  PIN o el PUK es m�s optimo marcar este par�metro a falso.
	 * 
	 * @throws ModuleNotFoundException No se ha encontrado el m�dulo PKCS#11
	 * 	adecuado instalado en el equipo.
	 * @throws IncorrectPINException El PIN no es correcto
	 * @throws IncorrectPUKException El PUK no es correcto
	 * @throws LockedPINException El PIN est� bloqueado
	 * @throws OpeningDeviceException Error durante el proceso de apertura
	 * @throws DeviceNotFoundException El dispositivo no existe
	 * @throws IAIKDLLNotFoundException No es posible cargar la DLL de IAIK, por 
	 * 	lo que no se puede trabajar con dispositivos PKCS#11
	 * @throws InitializeProviderException No es posible inicializar el proveedor PKCS#11 de Sun
	 */
	public Pkcs11Manager(Pkcs11Device device, String password, boolean isPUK, boolean withKeystore) throws ModuleNotFoundException, 
		IncorrectPINException, IncorrectPUKException, LockedPINException, OpeningDeviceException, 
		DeviceNotFoundException, IAIKDLLNotFoundException, InitializeProviderException {

		initialize(device, password, isPUK, withKeystore);
	}
	
	/**
	 *  Lo mismo que el metodo Pkcs11Manager(Pkcs11Device device, String password, boolean isPUK, boolean withKeystore), pero pasandole customAliases
	 */
	public Pkcs11Manager(Pkcs11Device device, String password, boolean isPUK, boolean withKeystore, CustomAliases customAliases) throws ModuleNotFoundException, 
		IncorrectPINException, IncorrectPUKException, LockedPINException, OpeningDeviceException, 
		DeviceNotFoundException, IAIKDLLNotFoundException, InitializeProviderException {
		this(device, password, isPUK, withKeystore);
		this.customAliases = customAliases;
	}

	/**
	 * Inicializa un gestor de PKCS#11 usando la implementaci�n del PKCS#11 
 	 * indicado. En caso de que hayan varios dispositivos conectados se 
 	 * elegir� el primero de ellos. Este m�todo se puede usar para el caso 
 	 * m�s habitual: que s�lo exista un dispositivo PKCS#11 conectado.
	 * 
	 * @param manufacturer Fabricante del dispositivo
	 * @param pin PIN para abrir el dispositivo
	 * @throws DeviceNotFoundException No existen dispositivos para la 
	 * 	liber�a PKCS#11 o no existe un dispositivo para el valor de 'tokenID'.
	 * @throws ModuleNotFoundException No se ha encontrado el m�dulo PKCS#11
	 * 	adecuado instalado en el equipo.
	 * @throws IncorrectPINException El PIN no es correcto
	 * @throws LockedPINException El PIN est� bloqueado
	 * @throws OpeningDeviceException Error durante el proceso de apertura
	 * @throws IAIKDLLNotFoundException No es posible cargar la DLL de IAIK, por 
	 * 	lo que no se puede trabajar con dispositivos PKCS#11
	 * @throws InitializeProviderException No es posible inicializar el proveedor PKCS#11 de Sun
	 */
	public Pkcs11Manager(Pkcs11Manufacturer manufacturer, String pin) throws DeviceNotFoundException, ModuleNotFoundException, 
		IncorrectPINException, LockedPINException, OpeningDeviceException, IAIKDLLNotFoundException, InitializeProviderException {
		super(manufacturer, pin);
	}
	
	/**
	 *  Lo mismo que el metodo Pkcs11Manager(Pkcs11Manufacturer manufacturer, String pin), pero pasandole customAliases
	 */
	public Pkcs11Manager(Pkcs11Manufacturer manufacturer, String pin, CustomAliases customAliases) throws DeviceNotFoundException, ModuleNotFoundException, 
		IncorrectPINException, LockedPINException, OpeningDeviceException, IAIKDLLNotFoundException, InitializeProviderException {
		this(manufacturer, pin);
		this.customAliases = customAliases;
	}

	/**
	 * Inicializa un gestor de PKCS#11 usando la implementaci�n del PKCS#11 
 	 * indicado. En caso de que hayan varios dispositivos conectados se 
 	 * elegir� el primero de ellos. Este m�todo se puede usar para el caso 
 	 * m�s habitual: que s�lo exista un dispositivo PKCS#11 conectado.
	 * 
	 * @param manufacturer Fabricante del dispositivo
	 * @param password PIN o PUK para abrir el dispositivo
	 * @param isPUK Determina si el primer par�metro es el PIN o el PUK
	 * 
	 * @throws DeviceNotFoundException No existen dispositivos para la 
	 * 	liber�a PKCS#11 o no existe un dispositivo para el valor de 'tokenID'.
	 * @throws ModuleNotFoundException No se ha encontrado el m�dulo PKCS#11
	 * 	adecuado instalado en el equipo.
	 * @throws IncorrectPINException El PIN (o el PUK) no es correcto
	 * @throws IncorrectPUKException El PUK no es correcto
	 * @throws LockedPINException El PIN est� bloqueado
	 * @throws OpeningDeviceException Error durante el proceso de apertura
	 * @throws IAIKDLLNotFoundException No es posible cargar la DLL de IAIK, por 
	 * 	lo que no se puede trabajar con dispositivos PKCS#11
	 * @throws InitializeProviderException No es posible inicializar el proveedor PKCS#11 de Sun
	 */
	public Pkcs11Manager(Pkcs11Manufacturer manufacturer, String password, boolean isPUK) throws DeviceNotFoundException, 
		ModuleNotFoundException, IncorrectPINException, IncorrectPUKException, LockedPINException, OpeningDeviceException, 
		IAIKDLLNotFoundException, InitializeProviderException {
		super(manufacturer, password, isPUK);
		
	}
	
	/**
	 *  Lo mismo que el metodo Pkcs11Manager(Pkcs11Manufacturer manufacturer, String password, boolean isPUK), pero pasandole customAliases
	 */
	public Pkcs11Manager(Pkcs11Manufacturer manufacturer, String password, boolean isPUK, CustomAliases customAliases) throws DeviceNotFoundException, 
		ModuleNotFoundException, IncorrectPINException, IncorrectPUKException, LockedPINException, OpeningDeviceException, 
		IAIKDLLNotFoundException, InitializeProviderException {
		this(manufacturer, password, isPUK);
		this.customAliases = customAliases;
	}

	//-- M�todos p�blicos
	
	/**
	 * M�todo que obtiene informaci�n de los dispositivos conectados para todas
	 * las librer�as PKCS#11 definidas en Arangi
	 * 
	 * @return Lista de objetos es.accv.arangi.base.device.model.Pkcs11Device 
	 * 	con	informaci�n de cada uno de los dispositivos encontrados
	 * @throws IAIKDLLNotFoundException No es posible cargar la DLL de IAIK, por 
	 * 	lo que no se puede trabajar con dispositivos PKCS#11
	 */
	public static List getConnectedDevices () throws IAIKDLLNotFoundException  {
		
		return es.accv.arangi.base.device.Pkcs11Manager.getConnectedDevices(getConnectedManufacturers());
		
	}
	
	/**
	 * Este m�todo trata de cargar e inicializar la lista de fabricantes PKCS#11 usados por Arangi. 
	 * Devuelve los nombres de aquellos m�dulos que se encuentran disponibles 
	 * en el equipo.
	 * 
	 * @return Lista de fabricantes disponibles en el equipo
	 * @throws IAIKDLLNotFoundException No es posible cargar la DLL de IAIK, por 
	 * 	lo que no se puede trabajar con dispositivos PKCS#11
	 */
	public static List getLoadableManufacturers () throws IAIKDLLNotFoundException {
		return es.accv.arangi.base.device.Pkcs11Manager.getLoadableManufacturers(getManufacturers());
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
		
		String[] aliases;
		try {
			aliases = getAliasNamesList();
		} catch (SearchingException e) {
			logger.info("[Pkcs11Manager.getSignatureAlias]::No se puede obtener la lista de alias del dispositivo", e);
			throw new LoadingObjectException ("No se puede obtener la lista de alias del dispositivo", e);
		}
		if (aliases == null || aliases.length == 0) {
			logger.info("[Pkcs11Manager.getSignatureAlias]::El dispositivo est� vac�o");
			throw new LoadingObjectException ("El dispositivo est� vac�o");
		}
		
		List lAlias = Arrays.asList(aliases);
		if (lAlias.contains(CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA)) {
			logger.debug ("[Pkcs11Manager.getSignatureAlias]::Encontrado alias de firma para certificado de ciudadano");
			return CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA;
		}
		if (lAlias.contains(CertificadoEmpleadoPublico.ALIAS_PKCS11)) {
			logger.debug ("[Pkcs11Manager.getSignatureAlias]::Encontrado alias de firma para empleado p�blico");
			return CertificadoEmpleadoPublico.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoEntidad.ALIAS_PKCS11)) {
			logger.debug ("[Pkcs11Manager.getSignatureAlias]::Encontrado alias de firma para entidades");
			return CertificadoEntidad.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoPertenenciaEmpresa.ALIAS_PKCS11)) {
			logger.debug ("[Pkcs11Manager.getSignatureAlias]::Encontrado alias de firma para pertenencia a empresa");
			return CertificadoPertenenciaEmpresa.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoSeudonimo.ALIAS_PKCS11)) {
			logger.debug ("[Pkcs11Manager.getSignatureAlias]::Encontrado alias de firma para seud�nimo");
			return CertificadoSeudonimo.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoRepresentante.ALIAS_PKCS11)) {
			logger.debug ("[Pkcs11Manager.getSignatureAlias]::Encontrado alias de firma para representante");
			return CertificadoRepresentante.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoDNIe.ALIAS_PKCS11_FIRMA)) {
			logger.debug ("[Pkcs11Manager.getSignatureAlias]::Encontrado alias de firma para DNIe");
			return CertificadoDNIe.ALIAS_PKCS11_FIRMA;
		}
		if (customAliases != null && customAliases.getSignatureAlias() != null){
			if (lAlias.contains(customAliases.getSignatureAlias())){
				logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de firma para customAlias");
				return customAliases.getSignatureAlias();
			}
		}
		
		logger.debug ("[Pkcs11Manager.getSignatureAlias]::No se ha encontrado ning�n alias conocido. Se devuelve el primero::" + aliases[0]);
		return aliases[0];
	}

	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getCipherAlias()
	 */
	public String getCipherAlias () throws LoadingObjectException {
		
		String[] aliases;
		try {
			aliases = getAliasNamesList();
		} catch (SearchingException e) {
			logger.info("[Pkcs11Manager.getCipherAlias]::No se puede obtener la lista de alias del dispositivo", e);
			throw new LoadingObjectException ("No se puede obtener la lista de alias del dispositivo", e);
		}
		if (aliases == null || aliases.length == 0) {
			logger.info("[Pkcs11Manager.getCipherAlias]::El dispositivo est� vac�o");
			throw new LoadingObjectException ("El dispositivo est� vac�o");
		}
		
		List lAlias = Arrays.asList(aliases);
		if (lAlias.contains(CertificadoCiudadano.ALIAS_KEYSTORE_CIFRADO)) {
			logger.debug ("[Pkcs11Manager.getCipherAlias]::Encontrado alias de cifrado para certificado de ciudadano");
			return CertificadoCiudadano.ALIAS_KEYSTORE_CIFRADO;
		}
		if (lAlias.contains(CertificadoEmpleadoPublico.ALIAS_PKCS11)) {
			logger.debug ("[Pkcs11Manager.getCipherAlias]::Encontrado alias de cifrado para empleado p�blico");
			return CertificadoEmpleadoPublico.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoEntidad.ALIAS_PKCS11)) {
			logger.debug ("[Pkcs11Manager.getCipherAlias]::Encontrado alias de cifrado para entidades");
			return CertificadoEntidad.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoDNIe.ALIAS_PKCS11_FIRMA)) {
			logger.debug ("[Pkcs11Manager.getCipherAlias]::Encontrado alias de cifrado para DNIe");
			return CertificadoDNIe.ALIAS_PKCS11_FIRMA;
		}
		if (customAliases != null && customAliases.getCipherAlias() != null){
			if (lAlias.contains(customAliases.getCipherAlias())){
				logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de cifrado para customAlias");
				return customAliases.getCipherAlias();
			}
		}
		
		logger.debug ("[Pkcs11Manager.getCipherAlias]::No se ha encontrado ning�n alias conocido. Se devuelve el primero::" + aliases[0]);
		return aliases[0];
	}
	
	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getAuthenticationAlias()
	 */
	public String getAuthenticationAlias () throws LoadingObjectException {
		
		String[] aliases;
		try {
			aliases = getAliasNamesList();
		} catch (SearchingException e) {
			logger.info("[Pkcs11Manager.getAuthenticationAlias]::No se puede obtener la lista de alias del dispositivo", e);
			throw new LoadingObjectException ("No se puede obtener la lista de alias del dispositivo", e);
		}
		if (aliases == null || aliases.length == 0) {
			logger.info("[Pkcs11Manager.getAuthenticationAlias]::El dispositivo est� vac�o");
			throw new LoadingObjectException ("El dispositivo est� vac�o");
		}
		
		List lAlias = Arrays.asList(aliases);
		if (lAlias.contains(CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA)) {
			logger.debug ("[Pkcs11Manager.getAuthenticationAlias]::Encontrado alias de autenticaci�n para certificado de ciudadano");
			return CertificadoCiudadano.ALIAS_KEYSTORE_FIRMA;
		}
		if (lAlias.contains(CertificadoEmpleadoPublico.ALIAS_PKCS11)) {
			logger.debug ("[Pkcs11Manager.getAuthenticationAlias]::Encontrado alias de autenticaci�n para empleado p�blico");
			return CertificadoEmpleadoPublico.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoEntidad.ALIAS_PKCS11)) {
			logger.debug ("[Pkcs11Manager.getAuthenticationAlias]::Encontrado alias de autenticaci�n para entidades");
			return CertificadoEntidad.ALIAS_PKCS11;
		}
		if (lAlias.contains(CertificadoDNIe.ALIAS_PKCS11_AUTENTICACION)) {
			logger.debug ("[Pkcs11Manager.getAuthenticationAlias]::Encontrado alias de autenticaci�n para DNIe");
			return CertificadoDNIe.ALIAS_PKCS11_AUTENTICACION;
		}
		if (customAliases != null && customAliases.getAuthenticationAlias() != null){
			if (lAlias.contains(customAliases.getAuthenticationAlias())){
				logger.debug ("[KeyStoremanager.getSignatureAlias]::Encontrado alias de autenticaci�n para customAlias");
				return customAliases.getAuthenticationAlias();
			}
		}
		
		logger.debug ("[Pkcs11Manager.getAuthenticationAlias]::No se ha encontrado ning�n alias conocido. Se devuelve el primero::" + aliases[0]);
		return aliases[0];
	}

	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getSignatureCertificate()
	 */
	public X509Certificate getSignatureCertificate () throws LoadingObjectException {
		try {
			return getCertificate(getSignatureAlias());
		} catch (SearchingException e) {
			throw new LoadingObjectException (e.getMessage());
		}
	}
		
	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getCipherCertificate()
	 */
	public X509Certificate getCipherCertificate () throws LoadingObjectException {
		try {
			return getCertificate(getCipherAlias());
		} catch (SearchingException e) {
			throw new LoadingObjectException (e.getMessage());
		}
	}
		
	/* (non-Javadoc)
	 * @see es.accv.arangi.device.ACCVDeviceManager#getAuthenticationCertificate()
	 */
	public X509Certificate getAuthenticationCertificate () throws LoadingObjectException {
		try {
			return getCertificate(getAuthenticationAlias());
		} catch (SearchingException e) {
			throw new LoadingObjectException (e.getMessage());
		}
	}
		
	//-- Privados
	
	private static Pkcs11Manufacturer[] getManufacturers () throws IAIKDLLNotFoundException {
		
		List<Pkcs11Manufacturer> lManufacturers = new ArrayList<Pkcs11Manufacturer>();
		try {
			lManufacturers.add(new Pkcs11SiemensManufacturer());
		} catch (NoSuitableDriversException e) {}
		try {
			lManufacturers.add(new Pkcs11GYDManufacturer());
		} catch (NoSuitableDriversException e) {}
		try {
			lManufacturers.add(new Pkcs11DNIeManufacturer());
		} catch (NoSuitableDriversException e) {}
		try {
			lManufacturers.add(new Pkcs11TYSManufacturer());
		} catch (NoSuitableDriversException e) {}
		try {
			lManufacturers.add(new Pkcs11GemaltoManufacturer());
		} catch (NoSuitableDriversException e) {}
		try {
			lManufacturers.add(new Pkcs11GemaltoR7Manufacturer());
		} catch (NoSuitableDriversException e) {}
		
		return lManufacturers.toArray(new Pkcs11Manufacturer[0]);
		
	}

	private static Pkcs11Manufacturer[] getConnectedManufacturers () throws IAIKDLLNotFoundException {

		List<Pkcs11Manufacturer> lManufacturers = new ArrayList<Pkcs11Manufacturer>();
		try {
			lManufacturers.add(new Pkcs11SiemensManufacturer());
		} catch (NoSuitableDriversException e) {}
		try {
			lManufacturers.add(new Pkcs11GYDManufacturer());
		} catch (NoSuitableDriversException e) {}
		try {
			lManufacturers.add(new Pkcs11DNIeManufacturer());
		} catch (NoSuitableDriversException e) {}
		try {
			lManufacturers.add(new Pkcs11TYSManufacturer());
		} catch (NoSuitableDriversException e) {}
		try {
			lManufacturers.add(new Pkcs11GemaltoManufacturer());
		} catch (NoSuitableDriversException e) {}
		try {
			lManufacturers.add(new Pkcs11GemaltoR7Manufacturer());
		} catch (NoSuitableDriversException e) {}
		
		return lManufacturers.toArray(new Pkcs11Manufacturer[0]);
		
	}


}
