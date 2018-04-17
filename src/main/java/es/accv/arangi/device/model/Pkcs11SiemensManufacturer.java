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
package es.accv.arangi.device.model;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;

import es.accv.arangi.base.device.model.Pkcs11Device;
import es.accv.arangi.base.device.model.Pkcs11Manufacturer;
import es.accv.arangi.base.exception.device.DeviceNotFoundException;
import es.accv.arangi.base.exception.device.IAIKDLLNotFoundException;
import es.accv.arangi.base.exception.device.IncorrectPINException;
import es.accv.arangi.base.exception.device.IncorrectPUKException;
import es.accv.arangi.base.exception.device.LockedPINException;
import es.accv.arangi.base.exception.device.ModuleNotFoundException;
import es.accv.arangi.base.exception.device.NoSuitableDriversException;
import es.accv.arangi.base.exception.device.OpeningDeviceException;

/**
 * Clase para tratar las particularidades del fabricante de tarjetas Siemens.
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class Pkcs11SiemensManufacturer extends Pkcs11Manufacturer {

	/**
	 * Logger de la clase
	 */
	Logger logger = Logger.getLogger(Pkcs11SiemensManufacturer.class);
	
	/**
	 * Constante con el nombre del fabricante
	 */
	public static final String MANUFACTURER_NAME = "siemens";
	
	/**
	 * Constante con el nombre del m�dulo para tratar tarjetas inicializadas con el API 2.2
	 */
	public static final String SIEMENS_2_2_MODULE_NAME = "CardOS_PKCS11.dll";
	
	/**
	 * Constante con el nombre del m�dulo para tratar tarjetas inicializadas con el API 3.2
	 */
	public static final String SIEMENS_3_2_MODULE_NAME = "siecap11.dll";
	
	/**
	 * Flag que indica que es necesario instalar la versi�n 2.2 de los drivers
	 */
	private boolean version22Needed = false;
	
	/**
	 * Flag que indica que es necesario instalar la versi�n 3.2 de los drivers
	 */
	private boolean version32Needed = false;
	
	/**
	 * Constructor
	 * 
	 * @throws IAIKDLLNotFoundException No se encuentra la DLL de IAIK
	 * @throws NoSuitableDriversException El manufacturer no dispone de drivers para
	 * 	funcionar en el entorno (Java 32 o 64 bits)
	 */
	public Pkcs11SiemensManufacturer() throws IAIKDLLNotFoundException, NoSuitableDriversException {
		super(MANUFACTURER_NAME, SIEMENS_2_2_MODULE_NAME);
	}

	/**
	 * Obtiene un objeto dispositivo usando la implementaci�n del PKCS#11 
 	 * del constructor. En caso de que hayan varios dispositivos conectados se 
 	 * elegir� el primero de ellos. Este m�todo se puede usar para el caso 
 	 * m�s habitual: que s�lo exista un dispositivo PKCS#11 conectado.
	 * 
	 * @param pin PIN para abrir el dispositivo
	 * @param isPUK Flag que indica si el pin hay que tratarlo como el PUK del
	 * 	dispositivo
	 * @return Dispositivo abierto con PIN o PUK
	 * @throws OpeningDeviceException No ha sido posible abrir el dispositivo
	 * @throws LockedPINException El PIN del dispositivo est� bloqueado
	 * @throws IncorrectPUKException El PUK es incorrecto
	 * @throws IncorrectPINException  El PIN es incorrecto
	 * @throws ModuleNotFoundException No se ha encontrado el m�dulo PKCS#11
	 * 	para tratar el dispositivo
	 * @throws DeviceNotFoundException No existen dispositivos para la 
	 * 	liber�a PKCS#11 o no existe un dispositivo para el valor de 'tokenID'.
	 */
	public Pkcs11Device getInstance (String pin, boolean isPUK) throws DeviceNotFoundException, ModuleNotFoundException, IncorrectPINException, IncorrectPUKException, LockedPINException, OpeningDeviceException {
		return getInstance(-1, pin, isPUK);
	}
	
	/**
	 * Obtiene un objeto dispositivo usando la implementaci�n del PKCS#11 
 	 * del constructor. Concretamente obtiene el dispositivo cuyo ID coincide
 	 * con el par�metro "deviceId".
	 * 
	 * @param deviceId ID del dispositivo
	 * @param pin PIN para abrir el dispositivo
	 * @param isPUK Flag que indica si el pin hay que tratarlo como el PUK del
	 * 	dispositivo
	 * @return Dispositivo abierto con PIN o PUK
	 * @throws OpeningDeviceException No ha sido posible abrir el dispositivo
	 * @throws LockedPINException El PIN del dispositivo est� bloqueado
	 * @throws IncorrectPUKException El PUK es incorrecto
	 * @throws IncorrectPINException  El PIN es incorrecto
	 * @throws ModuleNotFoundException No se ha encontrado el m�dulo PKCS#11
	 * 	para tratar el dispositivo
	 * @throws DeviceNotFoundException No existen dispositivos para la 
	 * 	liber�a PKCS#11 o no existe un dispositivo para el valor de 'tokenID'.
	 */
	public Pkcs11Device getInstance (long deviceId, String pin, boolean isPUK) throws DeviceNotFoundException, ModuleNotFoundException, IncorrectPINException, IncorrectPUKException, LockedPINException, OpeningDeviceException {
		logger.debug("[Pkcs11SiemensManufacturer.getInstance]::Entrada::" + Arrays.asList (new Object [] { deviceId, isPUK, iaikDLLFile } ));
		
		//-- Pruebo con la versi�n de la 2.2
		this.pkcs11Lib = SIEMENS_2_2_MODULE_NAME;
		Pkcs11Device device22 = null;
		try {
			device22 = super.getInstance(deviceId, pin, isPUK); 
			if (testWrite (device22)) {
				this.pkcs11LibPath = getPkcs11LibPaths().get(SIEMENS_2_2_MODULE_NAME);
				return device22;
			} else {
				logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El m�dulo " + SIEMENS_2_2_MODULE_NAME + " no es capaz de escribir en el dispositivo");
			}
		} catch (ModuleNotFoundException e) {
			//-- El m�dulo no est� instalado
			logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El m�dulo " + SIEMENS_2_2_MODULE_NAME + " no est� instalado");
		} catch (DeviceNotFoundException e) {
			logger.debug("[Pkcs11SiemensManufacturer.getInstance]::No hay ning�n dispositivo para la versi�n 2.2 del driver de Siemens");
		}
		
		//-- El m�dulo 2.2 no est� instalado, pruebo con la versi�n de la 3.2
		this.pkcs11Lib = SIEMENS_3_2_MODULE_NAME;
		Pkcs11Device device32 = null;
		try {
			device32 = super.getInstance(deviceId, pin, isPUK);
			if (testWrite (device32)) {
				this.pkcs11LibPath = getPkcs11LibPaths().get(SIEMENS_3_2_MODULE_NAME);
				return device32;
			} else {
				logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El m�dulo " + SIEMENS_3_2_MODULE_NAME + " no es capaz de escribir en el dispositivo");
			}
		} catch (ModuleNotFoundException e) {
			//-- El m�dulo no est� instalado
			logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El m�dulo " + SIEMENS_3_2_MODULE_NAME + " no est� instalado");
			throw new ModuleNotFoundException ("No hay instalado ning�n m�dulo PKCS#11 de Siemens", e);
		} 
		
		//-- Ning�n m�dulo es capaz de escribir en la tarjeta
		logger.info("[Pkcs11SiemensManufacturer.getInstance]::Ninguno de los m�dulos es capaz de escribir en el dispositivo");
		if (device22 != null) {
			logger.info("[Pkcs11SiemensManufacturer.getInstance]::Es necesario instalar la versi�n 3.2 de los m�dulos PKCS#11 Siemens");
			version32Needed = true;
			return device22;
		}
		if (device32 != null) {
			logger.info("[Pkcs11SiemensManufacturer.getInstance]::Es necesario instalar la versi�n 2.2 de los m�dulos PKCS#11 Siemens");
			version22Needed = true;
			return device32;
		}
		
		//-- No se llegar� aqu�
		return null;
	}
	
	/**
	 * Obtiene un objeto dispositivo usando la implementaci�n del PKCS#11 
 	 * del constructor. En caso de que hayan varios dispositivos conectados se 
 	 * elegir� el primero de ellos. Este m�todo se puede usar para el caso 
 	 * m�s habitual: que s�lo exista un dispositivo PKCS#11 conectado.<br><br>
 	 * 
 	 * El dispositivo obtenido no est� abierto con PIN ni PUK, por lo que su
 	 * utilizaci�n se limitar� a obtener informaci�n de los certificados que
 	 * almacena e informaci�n general, como su n�mero de serie.
	 * 
	 * @return Dispositivo sin abrir
	 * @throws OpeningDeviceException No ha sido posible obtener una sesi�n en
	 * 	el dispositivo
	 * @throws ModuleNotFoundException No se ha encontrado el m�dulo PKCS#11
	 * 	para tratar el dispositivo
	 * @throws DeviceNotFoundException No existen dispositivos para la 
	 * 	librer�a PKCS#11 o no existe un dispositivo para el valor de 'tokenID'.
	 */
	public Pkcs11Device getInstance () throws DeviceNotFoundException, ModuleNotFoundException, OpeningDeviceException {
		return getInstance(-1);
	}
	
	/**
	 * Obtiene un objeto dispositivo usando la implementaci�n del PKCS#11 
 	 * del constructor. Concretamente obtiene el dispositivo cuyo ID coincide
 	 * con el par�metro "deviceId".<br><br>
	 * 
 	 * El dispositivo obtenido no est� abierto con PIN ni PUK, por lo que su
 	 * utilizaci�n se limitar� a obtener informaci�n de los certificados que
 	 * almacena e informaci�n general, como su n�mero de serie.
	 *
	 * @param deviceId ID del dispositivo
	 * @throws OpeningDeviceException No ha sido posible obtener una sesi�n en
	 * 	el dispositivo
	 * @throws IAIKDLLNotFoundException No se ha encontrado la DLL de IAIK
	 * @throws ModuleNotFoundException No se ha encontrado el m�dulo PKCS#11
	 * 	para tratar el dispositivo
	 * @throws DeviceNotFoundException No existen dispositivos para la 
	 * 	librer�a PKCS#11 o no existe un dispositivo para el valor de 'tokenID'.
	 */
	public Pkcs11Device getInstance (long deviceId) throws DeviceNotFoundException, ModuleNotFoundException, OpeningDeviceException {
		logger.debug("[Pkcs11SiemensManufacturer.getInstance]::Entrada::" + Arrays.asList (new Object [] { deviceId } ));
		
		//-- Pruebo con la versi�n de la 2.2
		this.pkcs11Lib = SIEMENS_2_2_MODULE_NAME;
		try {
			return super.getInstance(deviceId);
		} catch (ModuleNotFoundException e) {
			//-- El m�dulo no est� instalado
			logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El m�dulo " + SIEMENS_2_2_MODULE_NAME + " no est� instalado");
		} 
		
		//-- El m�dulo 2.2 no est� instalado, pruebo con la versi�n de la 3.2
		this.pkcs11Lib = SIEMENS_3_2_MODULE_NAME;
		try {
			return super.getInstance(deviceId);
		} catch (ModuleNotFoundException e) {
			//-- El m�dulo no est� instalado
			logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El m�dulo " + SIEMENS_3_2_MODULE_NAME + " no est� instalado");
			throw new ModuleNotFoundException ("No hay instalado ning�n m�dulo PKCS#11 de Siemens", e);
		} 
		
	}
	
	/**
	 * Comprueba si el m�dulo del fabricante est� disponible en el equipo
	 * 
	 * @return Cierto si el m�dulo est� presente
	 */
	public boolean isModulePresent () {
		
		//-- Pruebo con la versi�n de la 2.2
		this.pkcs11Lib = SIEMENS_2_2_MODULE_NAME;
		if (super.isModulePresent()) {
			return true;
		} else {
			//-- Pruebo con la versi�n de la 3.2
			this.pkcs11Lib = SIEMENS_3_2_MODULE_NAME;
			return super.isModulePresent();
		}
	}
	
	/**
	 * Tras la inicializaci�n determina si es necesario tener instalada la
	 * versi�n 2.2 de los drivers para poder escribir en el dispositivo
	 * 	
	 * @return Cierto si son necesarios los drivers 2.2
	 */
	public boolean isVersion22Needed() {
		return version22Needed;
	}

	/**
	 * Tras la inicializaci�n determina si es necesario tener instalada la
	 * versi�n 3.2 de los drivers para poder escribir en el dispositivo
	 * 	
	 * @return Cierto si son necesarios los drivers 3.2
	 */
	public boolean isVersion32Needed() {
		return version32Needed;
	}

	/**
	 * M�todo que obtiene informaci�n de los dispositivos conectados para el
	 * fabricante
	 * 
	 * @return Lista de objetos de tipo Pkcs11Device
	 * @throws ModuleNotFoundException No se puede cargar el m�dulo
	 * @throws DeviceNotFoundException No se ha obtenido ning�n dispositivo para el m�dulo
	 * @throws OpeningDeviceException No se puede obtener una sesi�n en el dispositivo
	 */
	public List getConnectedDevices () throws ModuleNotFoundException, DeviceNotFoundException, OpeningDeviceException  {
		
		logger.debug("[Pkcs11Manufacturer.getConnectedDevices]::Entrada::" + this.pkcs11Lib);
		
		//-- Buscar elementos para cada liber�a
		List lDevices = new ArrayList();
		
		//-- Obtener el m�dulo
		Module module22 = null;
		try {
			//-- Pruebo con la versi�n de la 2.2
			module22 = Module.getInstance(SIEMENS_2_2_MODULE_NAME, this.iaikDLLFile.getAbsolutePath());
			this.pkcs11Lib = SIEMENS_2_2_MODULE_NAME;
			logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::Se ha cargado el m�dulo '" + SIEMENS_2_2_MODULE_NAME + "'");
		} catch (IOException e) {
			logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::No ha sido posible cargar el m�dulo '" + SIEMENS_2_2_MODULE_NAME + "'");
		}
		
		if (module22 != null) {
			//-- Obtener los tokens para el m�dulo
			Token[] tokens = null;
			try {
				tokens = getTokens(module22, getTreatableManufacturerIds());
			} catch (DeviceNotFoundException e) {
				logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::No ha sido posible obtener la lista de dispositivos conectados para el m�dulo '" + this.pkcs11Lib + "'::" + e.getMessage());
			}
			
			if (tokens != null) {
				//-- Para cada token: abrir sesi�n
				for (int i = 0; i < tokens.length; i++) {
					try {
						lDevices.add (new Pkcs11Device (false, this, this.pkcs11Lib, module22, tokens[i], tokens[i].getTokenInfo(), getSession(tokens[i])));
					} catch (TokenException e) {
						// -- no se puede obtener la informaci�n del token
						logger.debug("[Pkcs11Manufacturer.getConnectedDevices]::No se puede obtener informaci�n del token", e);
					}
				}
			}
		}
		
		Module module32 = null;
		try {
			//-- Pruebo con la versi�n de la 2.2
			module32 = Module.getInstance(SIEMENS_3_2_MODULE_NAME, this.iaikDLLFile.getAbsolutePath());
			this.pkcs11Lib = SIEMENS_3_2_MODULE_NAME;
		} catch (IOException e1) {
			logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::No ha sido posible cargar el m�dulo '" + SIEMENS_3_2_MODULE_NAME + "'");
		}
		
		if (module22 == null && module32 == null) {
			throw new ModuleNotFoundException ("Ninguno de los m�dulos de Siemens ha podido ser cargado.");
		}
		
		if (module32 != null) {
			//-- Obtener los tokens para el m�dulo
			Token[] tokens = null;
			try {
				tokens = getTokens(module32, getTreatableManufacturerIds());
			} catch (DeviceNotFoundException e) {
				logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::No ha sido posible obtener la lista de dispositivos conectados para el m�dulo '" + this.pkcs11Lib + "'::" + e.getMessage());
			}
			
			if (tokens != null) {
				//-- Para cada token: abrir sesi�n si no existia ya el token abierto por la 2.2
				for (int i = 0; i < tokens.length; i++) {
					
					try {
						if (!existeTokenEnLista (tokens[i], lDevices)) {
							lDevices.add (new Pkcs11Device (false, this, this.pkcs11Lib, module22, tokens[i], tokens[i].getTokenInfo(), getSession(tokens[i])));
						}
					} catch (TokenException e) {
						// -- no se puede obtener la informaci�n del token
						logger.debug("[Pkcs11Manufacturer.getConnectedDevices]::No se puede obtener informaci�n del token", e);
					}
				}
			}
		}
		
		//-- Si no hay dispositivos lanzar excepci�n
		if (lDevices.isEmpty()) {
			logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::No ha sido posible obtener la lista de dispositivos conectados para Siemens");
			throw new DeviceNotFoundException("No hay dispositivos conectados para Siemens");
		}
		
		//-- Devolver tabla
		return lDevices;
			
	}

	//-- Implementaci�n del m�todos abstractos
	
	@Override
	protected String[] getX86LibrariesNames() {
		return new String[] {
				// 2.2 (necesitan instalaci�n aparte)
				// 3.2
				"siecadu8.dll",
				"siecacrd.dll",
				"gmp4_2_1.dll",
				"siecaces.dll",
				"siecap15.dll",
				"siecap11.dll"
		};
	}

	@Override
	protected String[] getX64LibrariesNames() {
		return new String[] {
		};
	}

	@Override
	protected String[] getX86ResourcesNames() {
		return new String[] {
				
		};
	}
	
	@Override
	protected String[] getX64ResourcesNames() {
		return new String[] {
				
		};
	}
	
	@Override
	protected Set getTreatableManufacturerIds() {
		return null;
	}

	@Override
	public int getPinLength() {
		return 8;
	}

	@Override
	public int getPukLength() {
		return 10;
	}

	@Override
	protected List<String> getPkcs11Libraries() {
		List<String> lPkcs11Libraries = new ArrayList<String>();
		lPkcs11Libraries.add(SIEMENS_2_2_MODULE_NAME);
		lPkcs11Libraries.add(SIEMENS_3_2_MODULE_NAME);
		
		return lPkcs11Libraries;
	}


	
	//-- M�todos privados
	
	/**
	 * Prueba si se puede escribir en la tarjeta
	 * 
	 * @param device Dispositivo a probar
	 * @return Cierto si se puede escribir
	 */
	private boolean testWrite(Pkcs11Device device) {
		return !device.getTokenInfo().isWriteProtected();
	}

	/*
	 * Comprueba que el token no est� ya en la lista de dispositivos. Para ello
	 * verifica que el ID del slot del token no est� ya en uno de los dispositivos
	 * de la lista.
	 */
	private boolean existeTokenEnLista(Token token, List lDevices) {
		for (Iterator iterator = lDevices.iterator(); iterator.hasNext();) {
			Pkcs11Device device = (Pkcs11Device) iterator.next();
			long a = device.getId();
			long b = token.getSlot().getSlotID();
			if(device.getId() == token.getSlot().getSlotID()) {
				return true;
			}
		}
		
		return false;
	}

	@Override
	protected boolean runInX64() {
		return false;
	}

	@Override
	protected boolean runInX86() {
		return true;
	}


}
