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

import es.accv.arangi.base.document.IDocument;
import es.accv.arangi.base.exception.device.AliasNotFoundException;
import es.accv.arangi.base.exception.device.CipherException;
import es.accv.arangi.base.exception.device.LoadingObjectException;
import es.accv.arangi.base.exception.document.HashingException;
import es.accv.arangi.base.exception.signature.SignatureException;

/**
 * Interfaz con los m�todos necesarios para simplificar los m�todos de la clase
 * DeviceManager de Arangi Base para adaptarla a los dispositivos de la ACCV,
 * que utilizan siempre los mismos alias, y el algoritmo de firma m�s habitual:
 * SHA1WithRSA.
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public interface ACCVDeviceManager {

	/**
	 * Firma el documento pasado como par�metro.
	 * 
	 * @param document Documento a firmar
	 * @return Array de bytes con la firma. La firma ser� el resultado de aplicar los algoritmos
	 * SHA-1 y RSA al documento.
	 * @throws HashingException No es posible obtener el hash del documento o su versi�n en 
	 * 	formato DER durante el proceso de firma
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws SignatureException Error durante el proceso de firma
	 */
	public abstract byte[] signDocument (IDocument document) 
		throws HashingException, LoadingObjectException, SignatureException;
	
	/**
	 * Firma el documento pasado como par�metro en forma de stream de lectura.
	 * 
	 * @param document Stream de lectura al contenido del documento a firmar
	 * @return Array de bytes con la firma. La firma ser� el resultado de aplicar los algoritmos
	 * SHA-1 y RSA al documento.
	 * @throws AliasNotFoundException El alias donde se encuentra la clave privada usada para
	 * 	realizar la firma no existe
	 * @throws HashingException No es posible obtener el hash del documento o su versi�n en 
	 * 	formato DER durante el proceso de firma
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws SignatureException Error durante el proceso de firma
	 */
	public abstract byte[] signDocument (InputStream document) 
		throws AliasNotFoundException, HashingException, LoadingObjectException, SignatureException;
	
	/**
	 * Firma un documento, cuyo hash se pasa como par�metro.
	 * 
	 * @param hash Hash del documento a firmar
	 * @return Array de bytes con la firma. La firma ser� el cifrado RSA del hash con la clave
	 * privada asociada al alias.
	 * @throws HashingException El hash pasado es nulo o no se puede obtener con �l el objeto
	 * 	DER para la firma
	 * @throws AliasNotFoundException El alias donde se encuentra la clave privada usada para
	 * 	realizar la firma no existe
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws CipherException Error durante el proceso de cifrado
	 */
	public abstract byte[] signBytesHash (byte[] hash) 
		throws HashingException, AliasNotFoundException, LoadingObjectException, CipherException;
	
	/**
	 * Obtiene alias para firmar contenido en el dispositivo.
	 * 
	 * @return Alias para firmar contenido en el dispositivo
	 * @throws LoadingObjectException El dispositivo est� vac�o o no se puede obtener el alias
	 */
	public String getSignatureAlias () throws LoadingObjectException;

	/**
	 * Obtiene alias para cifrar contenido en el dispositivo.
	 * 
	 * @return Alias para cifrar contenido en el dispositivo
	 * @throws LoadingObjectException El dispositivo est� vac�o o no se puede obtener el alias
	 */
	public String getCipherAlias () throws LoadingObjectException;

	/**
	 * Obtiene alias para autenticar contenido en el dispositivo.
	 * 
	 * @return Alias para autenticar contenido en el dispositivo
	 * @throws LoadingObjectException El dispositivo est� vac�o o no se puede obtener el alias
	 */
	public String getAuthenticationAlias () throws LoadingObjectException;

	/**
	 * Obtiene el certificado para firmar que contiene el dispositivo
	 * 
	 * @return Certificado para firmar contenido en el dispositivo
	 * @throws LoadingObjectException El dispositivo est� vac�o o no se puede obtener el certificado
	 */
	public abstract X509Certificate getSignatureCertificate() throws LoadingObjectException;

	/**
	 * Obtiene el certificado para cifrar que contiene el dispositivo
	 * 
	 * @return Certificado para cifrar contenido en el dispositivo
	 * @throws LoadingObjectException El dispositivo est� vac�o o no se puede obtener el certificado
	 */
	public abstract X509Certificate getCipherCertificate() throws LoadingObjectException;

	/**
	 * Obtiene el certificado para autenticar que contiene el dispositivo
	 * 
	 * @return Certificado para autenticar contenido en el dispositivo
	 * @throws LoadingObjectException El dispositivo est� vac�o o no se puede obtener el certificado
	 */
	public abstract X509Certificate getAuthenticationCertificate() throws LoadingObjectException;

}
