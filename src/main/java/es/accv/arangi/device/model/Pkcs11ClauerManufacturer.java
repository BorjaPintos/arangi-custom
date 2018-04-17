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

import java.util.Set;

import org.apache.log4j.Logger;

import es.accv.arangi.base.device.model.Pkcs11Manufacturer;
import es.accv.arangi.base.exception.device.IAIKDLLNotFoundException;
import es.accv.arangi.base.exception.device.NoSuitableDriversException;

/**
 * Clase para tratar las particularidades del fabricante de tarjetas del DNIe.
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class Pkcs11ClauerManufacturer extends Pkcs11Manufacturer {

	/**
	 * Logger de la clase
	 */
	Logger logger = Logger.getLogger(Pkcs11ClauerManufacturer.class);
	
	/**
	 * Constante con el nombre del fabricante
	 */
	public static final String MANUFACTURER_NAME = "clauer";
	
	/**
	 * Constante con el nombre del m�dulo para tratar tarjetas
	 */
	public static final String MODULE_NAME = "pkcs11-win.dll";
	
	/**
	 * Constructor
	 * 
	 * @throws IAIKDLLNotFoundException No se encuentra la DLL de IAIK
	 * @throws NoSuitableDriversException El manufacturer no dispone de drivers para
	 * 	funcionar en el entorno (Java 32 o 64 bits)
	 */
	public Pkcs11ClauerManufacturer() throws IAIKDLLNotFoundException, NoSuitableDriversException {
		super(MANUFACTURER_NAME, MODULE_NAME);
	}

	//-- Implementaci�n del m�todos abstractos
	
	@Override
	protected String[] getX86LibrariesNames() {
		return new String[] {
				
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
		return 8;
	}

	@Override
	protected boolean runInX64() {
		return false;
	}

	@Override
	protected boolean runInX86() {
		return true;
	}

	//-- M�todos privados
	

}
