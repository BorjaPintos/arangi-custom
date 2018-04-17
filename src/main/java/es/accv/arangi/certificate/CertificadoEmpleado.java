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
package es.accv.arangi.certificate;


/**
 * Interfaz para los certificados de empleado
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� Manuel Guti�rrez N��ez</a>
 *
 */
public interface CertificadoEmpleado {

	/**
	 * M�todo que obtiene el CIF de la entidad suscriptora del certificado.
	 * 
	 * @return CIF de la entidad suscriptora del certificado
	 */
	public String getEntityCIF();
	
	/**
	 * M�todo que obtiene el nombre de la entidad suscriptora del certificado.
	 * 
	 * @return Nombre de la entidad suscriptora del certificado
	 */
	public String getEntityName();

	/**
	 * Devuelve la Unidad, dentro de la Administraci�n, en la que est� incluida el suscriptor
	 * del certificado.
	 * 
	 * @return Organization Unit del titular del certificado.
	 */
	public String getOrganizationalUnit();
	
	/**
	 * M�todo que obtiene el cargo del Empleado P�blico.
	 * 
	 * @return Cargo del Empleado P�blico
	 */
	public String getPosition();
	
	/**
	 * M�todo que obtiene el valor diferenciador para este tipo
	 * de certificados
	 */
	public String getNRPPseudonym();


}
