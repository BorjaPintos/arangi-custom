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
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
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
	 * Constante con el nombre del módulo para tratar tarjetas inicializadas con el API 2.2
	 */
	public static final String SIEMENS_2_2_MODULE_NAME = "CardOS_PKCS11.dll";
	
	/**
	 * Constante con el nombre del módulo para tratar tarjetas inicializadas con el API 3.2
	 */
	public static final String SIEMENS_3_2_MODULE_NAME = "siecap11.dll";
	
	/**
	 * Flag que indica que es necesario instalar la versión 2.2 de los drivers
	 */
	private boolean version22Needed = false;
	
	/**
	 * Flag que indica que es necesario instalar la versión 3.2 de los drivers
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
	 * Obtiene un objeto dispositivo usando la implementación del PKCS#11 
 	 * del constructor. En caso de que hayan varios dispositivos conectados se 
 	 * elegirá el primero de ellos. Este método se puede usar para el caso 
 	 * más habitual: que sólo exista un dispositivo PKCS#11 conectado.
	 * 
	 * @param pin PIN para abrir el dispositivo
	 * @param isPUK Flag que indica si el pin hay que tratarlo como el PUK del
	 * 	dispositivo
	 * @return Dispositivo abierto con PIN o PUK
	 * @throws OpeningDeviceException No ha sido posible abrir el dispositivo
	 * @throws LockedPINException El PIN del dispositivo está bloqueado
	 * @throws IncorrectPUKException El PUK es incorrecto
	 * @throws IncorrectPINException  El PIN es incorrecto
	 * @throws ModuleNotFoundException No se ha encontrado el módulo PKCS#11
	 * 	para tratar el dispositivo
	 * @throws DeviceNotFoundException No existen dispositivos para la 
	 * 	libería PKCS#11 o no existe un dispositivo para el valor de 'tokenID'.
	 */
	public Pkcs11Device getInstance (String pin, boolean isPUK) throws DeviceNotFoundException, ModuleNotFoundException, IncorrectPINException, IncorrectPUKException, LockedPINException, OpeningDeviceException {
		return getInstance(-1, pin, isPUK);
	}
	
	/**
	 * Obtiene un objeto dispositivo usando la implementación del PKCS#11 
 	 * del constructor. Concretamente obtiene el dispositivo cuyo ID coincide
 	 * con el parámetro "deviceId".
	 * 
	 * @param deviceId ID del dispositivo
	 * @param pin PIN para abrir el dispositivo
	 * @param isPUK Flag que indica si el pin hay que tratarlo como el PUK del
	 * 	dispositivo
	 * @return Dispositivo abierto con PIN o PUK
	 * @throws OpeningDeviceException No ha sido posible abrir el dispositivo
	 * @throws LockedPINException El PIN del dispositivo está bloqueado
	 * @throws IncorrectPUKException El PUK es incorrecto
	 * @throws IncorrectPINException  El PIN es incorrecto
	 * @throws ModuleNotFoundException No se ha encontrado el módulo PKCS#11
	 * 	para tratar el dispositivo
	 * @throws DeviceNotFoundException No existen dispositivos para la 
	 * 	libería PKCS#11 o no existe un dispositivo para el valor de 'tokenID'.
	 */
	public Pkcs11Device getInstance (long deviceId, String pin, boolean isPUK) throws DeviceNotFoundException, ModuleNotFoundException, IncorrectPINException, IncorrectPUKException, LockedPINException, OpeningDeviceException {
		logger.debug("[Pkcs11SiemensManufacturer.getInstance]::Entrada::" + Arrays.asList (new Object [] { deviceId, isPUK, iaikDLLFile } ));
		
		//-- Pruebo con la versión de la 2.2
		this.pkcs11Lib = SIEMENS_2_2_MODULE_NAME;
		Pkcs11Device device22 = null;
		try {
			device22 = super.getInstance(deviceId, pin, isPUK); 
			if (testWrite (device22)) {
				this.pkcs11LibPath = getPkcs11LibPaths().get(SIEMENS_2_2_MODULE_NAME);
				return device22;
			} else {
				logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El módulo " + SIEMENS_2_2_MODULE_NAME + " no es capaz de escribir en el dispositivo");
			}
		} catch (ModuleNotFoundException e) {
			//-- El módulo no está instalado
			logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El módulo " + SIEMENS_2_2_MODULE_NAME + " no está instalado");
		} catch (DeviceNotFoundException e) {
			logger.debug("[Pkcs11SiemensManufacturer.getInstance]::No hay ningún dispositivo para la versión 2.2 del driver de Siemens");
		}
		
		//-- El módulo 2.2 no está instalado, pruebo con la versión de la 3.2
		this.pkcs11Lib = SIEMENS_3_2_MODULE_NAME;
		Pkcs11Device device32 = null;
		try {
			device32 = super.getInstance(deviceId, pin, isPUK);
			if (testWrite (device32)) {
				this.pkcs11LibPath = getPkcs11LibPaths().get(SIEMENS_3_2_MODULE_NAME);
				return device32;
			} else {
				logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El módulo " + SIEMENS_3_2_MODULE_NAME + " no es capaz de escribir en el dispositivo");
			}
		} catch (ModuleNotFoundException e) {
			//-- El módulo no está instalado
			logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El módulo " + SIEMENS_3_2_MODULE_NAME + " no está instalado");
			throw new ModuleNotFoundException ("No hay instalado ningún módulo PKCS#11 de Siemens", e);
		} 
		
		//-- Ningún módulo es capaz de escribir en la tarjeta
		logger.info("[Pkcs11SiemensManufacturer.getInstance]::Ninguno de los módulos es capaz de escribir en el dispositivo");
		if (device22 != null) {
			logger.info("[Pkcs11SiemensManufacturer.getInstance]::Es necesario instalar la versión 3.2 de los módulos PKCS#11 Siemens");
			version32Needed = true;
			return device22;
		}
		if (device32 != null) {
			logger.info("[Pkcs11SiemensManufacturer.getInstance]::Es necesario instalar la versión 2.2 de los módulos PKCS#11 Siemens");
			version22Needed = true;
			return device32;
		}
		
		//-- No se llegará aquí
		return null;
	}
	
	/**
	 * Obtiene un objeto dispositivo usando la implementación del PKCS#11 
 	 * del constructor. En caso de que hayan varios dispositivos conectados se 
 	 * elegirá el primero de ellos. Este método se puede usar para el caso 
 	 * más habitual: que sólo exista un dispositivo PKCS#11 conectado.<br><br>
 	 * 
 	 * El dispositivo obtenido no está abierto con PIN ni PUK, por lo que su
 	 * utilización se limitará a obtener información de los certificados que
 	 * almacena e información general, como su número de serie.
	 * 
	 * @return Dispositivo sin abrir
	 * @throws OpeningDeviceException No ha sido posible obtener una sesión en
	 * 	el dispositivo
	 * @throws ModuleNotFoundException No se ha encontrado el módulo PKCS#11
	 * 	para tratar el dispositivo
	 * @throws DeviceNotFoundException No existen dispositivos para la 
	 * 	librería PKCS#11 o no existe un dispositivo para el valor de 'tokenID'.
	 */
	public Pkcs11Device getInstance () throws DeviceNotFoundException, ModuleNotFoundException, OpeningDeviceException {
		return getInstance(-1);
	}
	
	/**
	 * Obtiene un objeto dispositivo usando la implementación del PKCS#11 
 	 * del constructor. Concretamente obtiene el dispositivo cuyo ID coincide
 	 * con el parámetro "deviceId".<br><br>
	 * 
 	 * El dispositivo obtenido no está abierto con PIN ni PUK, por lo que su
 	 * utilización se limitará a obtener información de los certificados que
 	 * almacena e información general, como su número de serie.
	 *
	 * @param deviceId ID del dispositivo
	 * @throws OpeningDeviceException No ha sido posible obtener una sesión en
	 * 	el dispositivo
	 * @throws IAIKDLLNotFoundException No se ha encontrado la DLL de IAIK
	 * @throws ModuleNotFoundException No se ha encontrado el módulo PKCS#11
	 * 	para tratar el dispositivo
	 * @throws DeviceNotFoundException No existen dispositivos para la 
	 * 	librería PKCS#11 o no existe un dispositivo para el valor de 'tokenID'.
	 */
	public Pkcs11Device getInstance (long deviceId) throws DeviceNotFoundException, ModuleNotFoundException, OpeningDeviceException {
		logger.debug("[Pkcs11SiemensManufacturer.getInstance]::Entrada::" + Arrays.asList (new Object [] { deviceId } ));
		
		//-- Pruebo con la versión de la 2.2
		this.pkcs11Lib = SIEMENS_2_2_MODULE_NAME;
		try {
			return super.getInstance(deviceId);
		} catch (ModuleNotFoundException e) {
			//-- El módulo no está instalado
			logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El módulo " + SIEMENS_2_2_MODULE_NAME + " no está instalado");
		} 
		
		//-- El módulo 2.2 no está instalado, pruebo con la versión de la 3.2
		this.pkcs11Lib = SIEMENS_3_2_MODULE_NAME;
		try {
			return super.getInstance(deviceId);
		} catch (ModuleNotFoundException e) {
			//-- El módulo no está instalado
			logger.debug("[Pkcs11SiemensManufacturer.getInstance]::El módulo " + SIEMENS_3_2_MODULE_NAME + " no está instalado");
			throw new ModuleNotFoundException ("No hay instalado ningún módulo PKCS#11 de Siemens", e);
		} 
		
	}
	
	/**
	 * Comprueba si el módulo del fabricante está disponible en el equipo
	 * 
	 * @return Cierto si el módulo está presente
	 */
	public boolean isModulePresent () {
		
		//-- Pruebo con la versión de la 2.2
		this.pkcs11Lib = SIEMENS_2_2_MODULE_NAME;
		if (super.isModulePresent()) {
			return true;
		} else {
			//-- Pruebo con la versión de la 3.2
			this.pkcs11Lib = SIEMENS_3_2_MODULE_NAME;
			return super.isModulePresent();
		}
	}
	
	/**
	 * Tras la inicialización determina si es necesario tener instalada la
	 * versión 2.2 de los drivers para poder escribir en el dispositivo
	 * 	
	 * @return Cierto si son necesarios los drivers 2.2
	 */
	public boolean isVersion22Needed() {
		return version22Needed;
	}

	/**
	 * Tras la inicialización determina si es necesario tener instalada la
	 * versión 3.2 de los drivers para poder escribir en el dispositivo
	 * 	
	 * @return Cierto si son necesarios los drivers 3.2
	 */
	public boolean isVersion32Needed() {
		return version32Needed;
	}

	/**
	 * Método que obtiene información de los dispositivos conectados para el
	 * fabricante
	 * 
	 * @return Lista de objetos de tipo Pkcs11Device
	 * @throws ModuleNotFoundException No se puede cargar el módulo
	 * @throws DeviceNotFoundException No se ha obtenido ningún dispositivo para el módulo
	 * @throws OpeningDeviceException No se puede obtener una sesión en el dispositivo
	 */
	public List getConnectedDevices () throws ModuleNotFoundException, DeviceNotFoundException, OpeningDeviceException  {
		
		logger.debug("[Pkcs11Manufacturer.getConnectedDevices]::Entrada::" + this.pkcs11Lib);
		
		//-- Buscar elementos para cada libería
		List lDevices = new ArrayList();
		
		//-- Obtener el módulo
		Module module22 = null;
		try {
			//-- Pruebo con la versión de la 2.2
			module22 = Module.getInstance(SIEMENS_2_2_MODULE_NAME, this.iaikDLLFile.getAbsolutePath());
			this.pkcs11Lib = SIEMENS_2_2_MODULE_NAME;
			logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::Se ha cargado el módulo '" + SIEMENS_2_2_MODULE_NAME + "'");
		} catch (IOException e) {
			logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::No ha sido posible cargar el módulo '" + SIEMENS_2_2_MODULE_NAME + "'");
		}
		
		if (module22 != null) {
			//-- Obtener los tokens para el módulo
			Token[] tokens = null;
			try {
				tokens = getTokens(module22, getTreatableManufacturerIds());
			} catch (DeviceNotFoundException e) {
				logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::No ha sido posible obtener la lista de dispositivos conectados para el módulo '" + this.pkcs11Lib + "'::" + e.getMessage());
			}
			
			if (tokens != null) {
				//-- Para cada token: abrir sesión
				for (int i = 0; i < tokens.length; i++) {
					try {
						lDevices.add (new Pkcs11Device (false, this, this.pkcs11Lib, module22, tokens[i], tokens[i].getTokenInfo(), getSession(tokens[i])));
					} catch (TokenException e) {
						// -- no se puede obtener la información del token
						logger.debug("[Pkcs11Manufacturer.getConnectedDevices]::No se puede obtener información del token", e);
					}
				}
			}
		}
		
		Module module32 = null;
		try {
			//-- Pruebo con la versión de la 2.2
			module32 = Module.getInstance(SIEMENS_3_2_MODULE_NAME, this.iaikDLLFile.getAbsolutePath());
			this.pkcs11Lib = SIEMENS_3_2_MODULE_NAME;
		} catch (IOException e1) {
			logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::No ha sido posible cargar el módulo '" + SIEMENS_3_2_MODULE_NAME + "'");
		}
		
		if (module22 == null && module32 == null) {
			throw new ModuleNotFoundException ("Ninguno de los módulos de Siemens ha podido ser cargado.");
		}
		
		if (module32 != null) {
			//-- Obtener los tokens para el módulo
			Token[] tokens = null;
			try {
				tokens = getTokens(module32, getTreatableManufacturerIds());
			} catch (DeviceNotFoundException e) {
				logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::No ha sido posible obtener la lista de dispositivos conectados para el módulo '" + this.pkcs11Lib + "'::" + e.getMessage());
			}
			
			if (tokens != null) {
				//-- Para cada token: abrir sesión si no existia ya el token abierto por la 2.2
				for (int i = 0; i < tokens.length; i++) {
					
					try {
						if (!existeTokenEnLista (tokens[i], lDevices)) {
							lDevices.add (new Pkcs11Device (false, this, this.pkcs11Lib, module22, tokens[i], tokens[i].getTokenInfo(), getSession(tokens[i])));
						}
					} catch (TokenException e) {
						// -- no se puede obtener la información del token
						logger.debug("[Pkcs11Manufacturer.getConnectedDevices]::No se puede obtener información del token", e);
					}
				}
			}
		}
		
		//-- Si no hay dispositivos lanzar excepción
		if (lDevices.isEmpty()) {
			logger.debug ("[Pkcs11Manufacturer.getConnectedDevices]::No ha sido posible obtener la lista de dispositivos conectados para Siemens");
			throw new DeviceNotFoundException("No hay dispositivos conectados para Siemens");
		}
		
		//-- Devolver tabla
		return lDevices;
			
	}

	//-- Implementación del métodos abstractos
	
	@Override
	protected String[] getX86LibrariesNames() {
		return new String[] {
				// 2.2 (necesitan instalación aparte)
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


	
	//-- Métodos privados
	
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
	 * Comprueba que el token no esté ya en la lista de dispositivos. Para ello
	 * verifica que el ID del slot del token no esté ya en uno de los dispositivos
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
