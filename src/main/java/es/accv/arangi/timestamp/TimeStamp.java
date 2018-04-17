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
package es.accv.arangi.timestamp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.log4j.Logger;
import org.bouncycastle.tsp.TimeStampToken;

import es.accv.arangi.base.exception.document.HashingException;
import es.accv.arangi.base.exception.document.InitDocumentException;
import es.accv.arangi.base.exception.timestamp.MalformedTimeStampException;
import es.accv.arangi.base.exception.timestamp.ResponseTimeStampException;
import es.accv.arangi.base.exception.timestamp.TimeStampServerConnectionException;

/**
 * Clase para trabajar con sellos de tiempo según la 
 * <a href="http://tools.ietf.org/rfc/rfc3161.txt" target="rfc">RFC-3161</a>.<br><br>
 * 
 * Si lo único que se quiere es obtener la hora actual es mejor utilizar la clase
 * es.accv.arangi.base.util.time.Time.<br><br>
 * 
 * NOTA: En la clase se utilizan indistintamente los términos <i>servidor de sello de 
 * tiempos</i> y <i>TSA - Time Stamp Authority</i><br><br>
 * 
 * Un ejemplo de uso sería: <br><br>
 * 
 * <code>
 * 	byte[] dataToStamp = "data to stamp".getBytes();<br>
 * 	TimeStamp timeStamp = TimeStamp.stampDocument (dataToStamp);<br><br>
 * 
 * 	//guardar sello<br>
 * 	Util.saveFile(new File ("/sellos/sello.ts"), timeStamp.toDER());<br><br>
 * 
 * 	//cargar el sello<br>
 *  TimeStamp timeStamp2 = new TimeStamp (new File ("/sellos/sello.ts"));
 * </code><br><br>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class TimeStamp extends es.accv.arangi.base.timestamp.TimeStamp {

	/*
	 * Logger de la clase
	 */
	static Logger logger = Logger.getLogger(TimeStamp.class);
	
	/**
	 * URL del servicio de sello de tiempos de la ACCV
	 */
	public static final String URL_ACCV_TSA_SERVER	= "http://tss.accv.es:8318/tsa";
	
	/**
	 * Constructor en base a un objeto sello de tiempos de Bouncy Castle
	 * 
	 * @param timeStamp Sello de tiempos de Bouncy Castle
	 */
	public TimeStamp (TimeStampToken timeStamp) {
		super(timeStamp);
	}
	
	/**
	 * Constructor en base a un array de bytes que contiene un sello de tiempo.
	 * 
	 * @param bytesTimeStamp Contenido de un objeto sello de tiempo
	 * @throws MalformedTimeStampException El objeto contenido en el stream de lectura no parece
	 * 	ser un sello de tiempo
	 */
	public TimeStamp(byte[] bytesTimeStamp) throws MalformedTimeStampException {
		super(bytesTimeStamp);
	}

	/**
	 * Constructor en base a un fichero que contiene un sello de tiempo.
	 * 
	 * @param fileTimeStamp Fichero que contiene un objeto sello de tiempo
	 * @throws MalformedTimeStampException El objeto contenido en el stream de lectura no parece
	 * 	ser un sello de tiempo
	 * @throws FileNotFoundException El fichero no existe
	 */
	public TimeStamp(File fileTimeStamp) throws MalformedTimeStampException, FileNotFoundException {
		super(fileTimeStamp);
	}

	/**
	 * Constructor en base a un stream de lectura que contiene el sello de tiempo.
	 * 
	 * @param isTimeStamp Stream de lectura a un objeto sello de tiempo
	 * @throws MalformedTimeStampException El objeto contenido en el stream de lectura no parece
	 * 	ser un sello de tiempo
	 */
	public TimeStamp(InputStream isTimeStamp) throws MalformedTimeStampException {
		super(isTimeStamp);
	}

	/**
	 * Método que obtiene un sello de tiempos de la TSA de la ACCV para los datos
	 * pasados como parámetro.
	 * 
	 * @param bytesToStamp Array de bytes con el contenido del documento a sellar
	 * @return Sello de tiempos de la ACCV sobre los datos pasados
	 * @throws TimeStampServerConnectionException Errores en la conexión con el servidor de sello
	 * 	de tiempos
	 * @throws MalformedTimeStampException El objeto devuelto por el servidor no parece ser un 
	 * 	sello de tiempos
	 * @throws ResponseTimeStampException La TSA ha devuelto una respuesta con un error
	 * @throws HashingException Error obteniendo el hash
	 */
	public static TimeStamp stampDocument (byte[] bytesToStamp) throws MalformedTimeStampException, ResponseTimeStampException, HashingException, TimeStampServerConnectionException {
		logger.debug ("[TimeStamp.stamp]::Entrada::" + bytesToStamp);
		
		//-- Obtener el sello 
		try {
			return new TimeStamp (es.accv.arangi.base.timestamp.TimeStamp.stampDocument(bytesToStamp, new URL(URL_ACCV_TSA_SERVER)).toDER());
		} catch (MalformedURLException e) {
			//-- La URL está bien formada (no se va a dar)
			return null;
		} 
	}
	
	/**
	 * Método que obtiene un sello de tiempos de la TSA de la ACCV para los datos
	 * contenidos en el fichero pasado como parámetro.
	 * 
	 * @param fileToStamp Fichero con los datos a sellar
	 * @return Sello de tiempos de la ACCV sobre los datos pasados
	 * @throws TimeStampServerConnectionException Errores en la conexión con el servidor de sello
	 * 	de tiempos
	 * @throws MalformedTimeStampException El objeto devuelto por el servidor no parece ser un 
	 * 	sello de tiempos
	 * @throws ResponseTimeStampException La TSA ha devuelto una respuesta con un error
	 * @throws HashingException Error obteniendo el hash
	 * @throws InitDocumentException El fichero a sellar es nulo o no existe
	 */
	public static TimeStamp stampDocument (File fileToStamp) throws MalformedTimeStampException, ResponseTimeStampException, HashingException, MalformedURLException, TimeStampServerConnectionException, InitDocumentException {
		logger.debug ("[TimeStamp.stamp]::Entrada::" + fileToStamp);
		
		//-- Obtener el sello 
		try {
			return new TimeStamp (es.accv.arangi.base.timestamp.TimeStamp.stampDocument(fileToStamp, new URL(URL_ACCV_TSA_SERVER)).toDER());
		} catch (MalformedURLException e) {
			//-- La URL está bien formada (no se va a dar)
			return null;
		} 
	}

	/**
	 * Método que obtiene un sello de tiempos de la TSA de la ACCV para los datos
	 * pasados como parámetro.
	 * 
	 * @param isToStamp Stream de lectura que apunta a los datos a sellar
	 * @return Sello de tiempos de la ACCV sobre los datos pasados
	 * @throws TimeStampServerConnectionException Errores en la conexión con el servidor de sello
	 * 	de tiempos
	 * @throws MalformedTimeStampException El objeto devuelto por el servidor no parece ser un 
	 * 	sello de tiempos
	 * @throws ResponseTimeStampException La TSA ha devuelto una respuesta con un error
	 * @throws HashingException Error obteniendo el hash
	 */
	public static TimeStamp stampDocument (InputStream isToStamp) throws MalformedTimeStampException, ResponseTimeStampException, HashingException, TimeStampServerConnectionException {
		logger.debug ("[TimeStamp.stamp]::Entrada::" + isToStamp);
		
		//-- Obtener el sello 
		try {
			return new TimeStamp (es.accv.arangi.base.timestamp.TimeStamp.stampDocument(isToStamp, new URL(URL_ACCV_TSA_SERVER)).toDER());
		} catch (MalformedURLException e) {
			//-- La URL está bien formada (no se va a dar)
			return null;
		} 
		
	}

	/**
	 * Método que obtiene un sello de tiempos de la TSA de la ACCV para los datos
	 * pasados como parámetro.
	 * 
	 * @param urlToStamp URL del documento cuyo contenido se desea sellar
	 * @return Sello de tiempos de la ACCV sobre los datos pasados
	 * @throws TimeStampServerConnectionException Errores en la conexión con el servidor de sello
	 * 	de tiempos
	 * @throws MalformedTimeStampException El objeto devuelto por el servidor no parece ser un 
	 * 	sello de tiempos
	 * @throws ResponseTimeStampException La TSA ha devuelto una respuesta con un error
	 * @throws HashingException Error obteniendo el hash
	 * @throws InitDocumentException No se puede obtener el documento en la URL
	 */
	public static TimeStamp stampDocument (URL urlToStamp) throws MalformedTimeStampException, ResponseTimeStampException, HashingException, TimeStampServerConnectionException, InitDocumentException {
		logger.debug ("[TimeStamp.stamp]::Entrada::" + urlToStamp);
		
		//-- Obtener el sello 
		try {
			return new TimeStamp (es.accv.arangi.base.timestamp.TimeStamp.stampDocument(urlToStamp, new URL(URL_ACCV_TSA_SERVER)).toDER());
		} catch (MalformedURLException e) {
			//-- La URL está bien formada (no se va a dar)
			return null;
		} 
		
	}

	/**
	 * Método que obtiene un sello de tiempo de un servidor de sello de tiempos.
	 * 
	 * @param hash Hash del documento cuyo contenido se desea sellar
	 * @throws FileNotFoundException El fichero no existe
	 * @throws TimeStampServerConnectionException Errores en la conexión con el servidor de sello
	 * 	de tiempos
	 * @throws MalformedTimeStampException El objeto devuelto por el servidor no parece ser un 
	 * 	sello de tiempos
	 * @throws ResponseTimeStampException La TSA ha devuelto una respuesta con un error
	 */
	public static TimeStamp stampHash (byte[] hash) throws TimeStampServerConnectionException, MalformedTimeStampException, ResponseTimeStampException {
		//-- Obtener el sello 
		try {
			return new TimeStamp (es.accv.arangi.base.timestamp.TimeStamp.stampHash(hash, new URL(URL_ACCV_TSA_SERVER)).toDER());
		} catch (MalformedURLException e) {
			//-- La URL está bien formada (no se va a dar)
			return null;
		} 
	}
	
	/**
	 * Obtiene la URL de la TSA de la ACCV
	 * 
	 * @return URL de la TSA de la ACCV
	 */
	public static URL getURLACCVTSA () {
		try {
			return new URL (URL_ACCV_TSA_SERVER);
		} catch (MalformedURLException e) {
			// No se va a dar, la URL está bien formada
			logger.info("[TimeStamp.getURLACCVTSA]::La URL de la ACCV no está bien formada: " + URL_ACCV_TSA_SERVER, e);
			return null;
		}
	}
}
