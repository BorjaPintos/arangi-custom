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
package es.accv.arangi.certificate.field;

import java.util.Date;

/**
 * Datos de representaci�n en base a la entrada en un bolet�n oficial
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� Manuel Guti�rrez N��ez</a>
 *
 */
public class DatosRepresentacionBoletinOficial {

	String boletin;
	Date fecha;
	String numeroResolucion;
	public String getBoletin() {
		return boletin;
	}
	public void setBoletin(String boletin) {
		this.boletin = boletin;
	}
	public Date getFecha() {
		return fecha;
	}
	public void setFecha(Date fecha) {
		this.fecha = fecha;
	}
	public String getNumeroResolucion() {
		return numeroResolucion;
	}
	public void setNumeroResolucion(String numeroResolucion) {
		this.numeroResolucion = numeroResolucion;
	}
	
}
