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
package es.accv.arangi.signature;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;

import org.w3c.dom.Document;

import es.accv.arangi.base.certificate.Certificate;
import es.accv.arangi.base.device.DeviceManager;
import es.accv.arangi.base.document.IDocument;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.device.LoadingObjectException;
import es.accv.arangi.base.exception.document.HashingException;
import es.accv.arangi.base.exception.signature.CounterSignatureException;
import es.accv.arangi.base.exception.signature.NoCoincidentDocumentException;
import es.accv.arangi.base.exception.signature.NoDocumentToSignException;
import es.accv.arangi.base.exception.signature.SignatureException;
import es.accv.arangi.base.exception.signature.SignatureNotFoundException;
import es.accv.arangi.base.exception.signature.XMLDocumentException;
import es.accv.arangi.base.exception.timestamp.MalformedTimeStampException;
import es.accv.arangi.base.exception.timestamp.ResponseTimeStampException;
import es.accv.arangi.base.signature.XAdESBESSignature;
import es.accv.arangi.base.signature.util.TSAData;
import es.accv.arangi.base.signature.util.XAdESAttachedSignatureOptions;
import es.accv.arangi.base.signature.util.XAdESDataObjectFormat;
import es.accv.arangi.base.signature.util.XAdESDetachedSignatureOptions;
import es.accv.arangi.base.util.validation.ValidationResult;
import es.accv.arangi.device.ACCVDeviceManager;
import es.accv.arangi.timestamp.TimeStamp;
import es.accv.arangi.util.ArangiUtil;

/**
 * Clase que maneja firmas en formato XAdES-T de acuerdo al estándar 
 * <a href="http://uri.etsi.org/01903/v1.3.2/ts_101903v010302p.pdf" target="etsi">
 * ETSI TS 101 903</a><br><br>
 * 
 * El servidor de Sellado de Tiempo utilizado para completar XAdES-BES o generar XAdES-T será el
 * proporcionado por la Agencia de tecnologia y certificación electrónica (ACCV): http://tss.accv.es:8318/tsa. 
 * 
 * Ejemplo de uso: <br><br>
 * 
 * <code> 
 * KeyStoreManager manager = new KeyStoreManager (..., ...);<br>
 * InputStreamDocument documentTexto = new InputStreamDocument (new FileInputStream (...));<br>
 * InputStreamDocument documentXML = new InputStreamDocument (new FileInputStream (...));<br>
 * File file = new File (...);<br>
 * URL url = new URL (...);<br><br>
 * 
 * //-- Genera una firma attached. El documento se guardará en la firma en base64<br>
 * XAdESTSignature signature1 = XAdESTSignature.signAttached(manager, documentTexto);<br><br>
 * 
 * //-- Genera una firma detached que referencia al fichero en disco<br>
 * XAdESTSignature signature2 = XAdESTSignature.signDetached(manager, file);<br><br>
 * 
 * //-- Genera una firma detached que referencia a "2011/04/29/certificados/CER-2584665.pdf"<br>
 * XAdESTSignature signature3 = XAdESTSignature.signDetached(manager, file, "2011/04/29/certificados/CER-2584665.pdf");<br><br>
 * 
 * //-- Genera una firma detached que referencia al fichero ubicado en la URL<br>
 * XAdESTSignature signature4 = XAdESTSignature.signDetached(manager, url);<br><br>
 * 
 * //-- Genera una firma attached dentro del propio documento<br>
 * XAdESTSignature signature5 = XAdESTSignature.signAttached(manager, documentoXML, "titulo", "documento");<br><br>
 * </code>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class XAdESTSignature extends es.accv.arangi.base.signature.XAdESTSignature {

	/**
	 * Construye el objeto en base a un XML que tiene el formato
	 * XAdES-T
	 * 
	 * @param xmlDocument Documento XML
	 */
	public XAdESTSignature(Document xmlDocument) {
		super(xmlDocument);
	}

	/**
	 * Construye el objeto en base a un fichero XAdES-T
	 * 
	 * @param xmlFile Fichero XAdES-T
	 * @throws FileNotFoundException El fichero no existe
	 * @throws XMLDocumentException El fichero no parece un XML válido
	 */
	public XAdESTSignature(File xmlFile) throws FileNotFoundException,
			XMLDocumentException {
		super(xmlFile);
	}
	
	/**
	 * Construye el objeto en base a un array de bytes.
	 * 
	 * @param signature Firma XAdES-T
	 * @throws XMLDocumentException El fichero no parece un XML válido
	 */
	public XAdESTSignature(byte[] signature) throws XMLDocumentException {
		super(signature);
	}

	/**
	 * Construye el objeto en base a un stream de lectura.
	 * 
	 * @param isSignature Firma XAdES-T
	 * @throws XMLDocumentException El fichero no parece un XML válido
	 */
	public XAdESTSignature(InputStream isSignature) throws XMLDocumentException {
		super(isSignature);
	}


	/**
	 * Construye el objeto en base a una firma XAdES-BES (o XAdES-EPES) añadiéndole un 
	 * sello de tiempo
	 * 
	 * @param besSignature Firma en formato XAdES-BES
	 * @throws HashingException Error obteniendo el hash del documento
	 * @throws NormalizeCertificateException Alguno de los certificados no puede ser 
	 * 	normalizado al formato reconocido por el proveedor criptográfico de Arangí o su 
	 * 	firma no es correcta o no puede ser analizada
	 * @throws NoDocumentToSignException La firma no es attached por lo que no hay documento con
	 * 	el que validarla. 
	 * @throws XMLDocumentException Error completando el XML del XAdES-BES a XAdES-T
	 * @throws MalformedTimeStampException El sello de tiempos obtenido no está bien formado
	 * @throws ResponseTimeStampException No se ha podido obtener correctamente el sello de tiempos
	 */
	public XAdESTSignature(XAdESBESSignature besSignature) throws HashingException, SignatureException, NormalizeCertificateException, NoDocumentToSignException, XMLDocumentException, MalformedTimeStampException, ResponseTimeStampException, MalformedURLException  {
		
		super(besSignature, ArangiUtil.getACCVCaList(), new URL (TimeStamp.URL_ACCV_TSA_SERVER));
		
	}

	/**
	 * Realiza una firma XAdES-T detached (el fichero no se incluirá en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Fichero a firmar
	 * @return Firma XADES-T
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESTSignature signDetached (ACCVDeviceManager manager, File document) throws LoadingObjectException, SignatureException, NoDocumentToSignException {

		return signDetached(manager, document, null, null, null);
		
	}
	
	/**
	 * Realiza una firma XAdES-T detached (el fichero no se incluirá en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Fichero a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param dof Información para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-T
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESTSignature signDetached (ACCVDeviceManager manager, File document, 
			String digitalSignatureAlgorithm, XAdESDataObjectFormat dof, String[] claimedRoles) throws LoadingObjectException, SignatureException, NoDocumentToSignException {
		
		try {
			return new XAdESTSignature (es.accv.arangi.base.signature.XAdESTSignature.signDetached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm,
				new URL (TimeStamp.URL_ACCV_TSA_SERVER), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv está bien formada
			return null;
		}
		
	}
	
	/**
	 * Realiza una firma XAdES-T detached (el fichero no se incluirá en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param urlDocument Documento a firmar. Se encuentra en una URL accesible.
	 * @return Firma XADES-T
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESTSignature signDetached (ACCVDeviceManager manager, URL urlDocument) throws LoadingObjectException, SignatureException, NoDocumentToSignException {
		
		return signDetached(manager, urlDocument, null, null, null);
		
	}
	
	/**
	 * Realiza una firma XAdES-T detached (el fichero no se incluirá en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param urlDocument Documento a firmar. Se encuentra en una URL accesible.
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param dof Información para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-T
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESTSignature signDetached (ACCVDeviceManager manager, URL urlDocument, 
			String digitalSignatureAlgorithm, XAdESDataObjectFormat dof,
			String[] claimedRoles) throws LoadingObjectException, SignatureException, NoDocumentToSignException {
		
		try {
			return new XAdESTSignature (es.accv.arangi.base.signature.XAdESTSignature.signDetached((DeviceManager) manager, 
					manager.getSignatureAlias(), urlDocument, digitalSignatureAlgorithm,
				new URL (TimeStamp.URL_ACCV_TSA_SERVER), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv está bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-T detached (el fichero no se incluirá en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Contenido a firmar. 
	 * @param reference Referencia al documento a firmar (se incluirá en el XAdES-T). Ej. Path al documento dentro de un gestor documental.
	 * @return Firma XADES-T
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESTSignature signDetached (ACCVDeviceManager manager, IDocument document, String reference) throws LoadingObjectException, SignatureException {
		
		return signDetached(manager, document, null, reference, null, null);
		
	}
	
	/**
	 * Realiza una firma XAdES-T detached (el fichero no se incluirá en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Contenido a firmar. 
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param reference Referencia al documento a firmar (se incluirá en el XAdES-T). Ej. Path al documento dentro de un gestor documental.
	 * @param dof Información para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-T
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESTSignature signDetached (ACCVDeviceManager manager, IDocument document, 
			String digitalSignatureAlgorithm, String reference,
			XAdESDataObjectFormat dof, String[] claimedRoles) throws LoadingObjectException, SignatureException {
		
		try {
			return new XAdESTSignature (es.accv.arangi.base.signature.XAdESTSignature.signDetached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm,
				reference, new URL (TimeStamp.URL_ACCV_TSA_SERVER), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv está bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-T detached (el fichero no se incluirá en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Contenido a firmar. 
	 * @param reference Referencia al documento a firmar (se incluirá en el XAdES-T). Ej. Path al documento dentro de un gestor documental.
	 * @param options Opciones para la firma
	 * @return Firma XADES-T
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 */
	public static XAdESTSignature signDetached (ACCVDeviceManager manager, IDocument document, 
			String reference, XAdESDetachedSignatureOptions options) throws LoadingObjectException, SignatureException {
		
		try {
			return new XAdESTSignature (es.accv.arangi.base.signature.XAdESTSignature.signDetached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, reference, new TSAData(new URL (TimeStamp.URL_ACCV_TSA_SERVER)), options).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv está bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-T atached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.
	 * 
	 * Si el documento es un XML y los parámetros <code>idToSign</code> y <code>signatureParent</code>
	 * no son nulos la firma y los campos propios de XAdES se añadirán al XML. En caso contrario el fichero 
	 * XAdES resultante seguirá la plantilla de Arangí, por ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Documento a firmar
	 * @param idToSign Valor del atributo 'ID' que indica lo que se firmará dentro del documento. Si tiene 
	 *  valor nulo el XML de la firma tendrá el formato por defecto de las firmas XAdES de Arangí.
	 * @param signatureParent Nombre del tag que será el padre de los nodos de firma. Si tiene valor nulo
	 * 	la firma colgará del nodo raíz.
	 * @return Firma XADES-T
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESTSignature signAttached (ACCVDeviceManager manager, IDocument document, String idToSign,
			String signatureParent) throws XMLDocumentException, LoadingObjectException, SignatureException  {
	
		return signAttached(manager, document, null, idToSign, signatureParent, null, null);
		
	}
	
	/**
	 * Realiza una firma XAdES-T atached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.
	 * 
	 * Si el documento es un XML y los parámetros <code>idToSign</code> y <code>signatureParent</code>
	 * no son nulos la firma y los campos propios de XAdES se añadirán al XML. En caso contrario el fichero 
	 * XAdES resultante seguirá la plantilla de Arangí, por ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Documento a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param idToSign Valor del atributo 'ID' que indica lo que se firmará dentro del documento. Si tiene 
	 *  valor nulo el XML de la firma tendrá el formato por defecto de las firmas XAdES de Arangí.
	 * @param signatureParent Nombre del tag que será el padre de los nodos de firma. Si tiene valor nulo
	 * 	la firma colgará del nodo raíz.
	 * @param dof Información para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-T
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESTSignature signAttached (ACCVDeviceManager manager, IDocument document, 
			String digitalSignatureAlgorithm, String idToSign,
			String signatureParent, XAdESDataObjectFormat dof, String[] claimedRoles) throws XMLDocumentException, LoadingObjectException, SignatureException  {
	
		try {
			return new XAdESTSignature (es.accv.arangi.base.signature.XAdESTSignature.signAttached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm, 
				idToSign, signatureParent, new URL (TimeStamp.URL_ACCV_TSA_SERVER), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv está bien formada
			return null;
		}

	}
	
	/**
	 * Realiza una firma XAdES-T atached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguirá la plantilla de Arangí. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Documento a firmar
	 * @return Firma XADES-T
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESTSignature signAttached (ACCVDeviceManager manager, IDocument document) throws XMLDocumentException, LoadingObjectException, SignatureException  {
		
		return signAttached(manager, document, (String)null, null);
		
	}
	
	/**
	 * Realiza una firma XAdES-T atached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguirá la plantilla de Arangí. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Documento a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param dof Información para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-T
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESTSignature signAttached (ACCVDeviceManager manager, IDocument document, 
			String digitalSignatureAlgorithm, XAdESDataObjectFormat dof, String[] claimedRoles) throws XMLDocumentException, LoadingObjectException, SignatureException  {
		
		try {
			return new XAdESTSignature (es.accv.arangi.base.signature.XAdESTSignature.signAttached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm,
				new URL (TimeStamp.URL_ACCV_TSA_SERVER), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv está bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-T attached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguirá la plantilla de Arangí. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Fichero a firmar
	 * @return Firma XADES-T
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESTSignature signAttached (ACCVDeviceManager manager, File document) throws LoadingObjectException, SignatureException, NoDocumentToSignException, XMLDocumentException {
		
		return signAttached(manager, document, null, null, null);

	}
	
	/**
	 * Realiza una firma XAdES-T attached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguirá la plantilla de Arangí. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Fichero a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param dof Información para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-T
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESTSignature signAttached (ACCVDeviceManager manager, File document, 
			String digitalSignatureAlgorithm, XAdESDataObjectFormat dof,
			String[] claimedRoles) throws LoadingObjectException, SignatureException, NoDocumentToSignException, XMLDocumentException {
		
		try {
			return new XAdESTSignature (es.accv.arangi.base.signature.XAdESTSignature.signAttached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm,
				new URL (TimeStamp.URL_ACCV_TSA_SERVER), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv está bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-T attached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguirá la plantilla de Arangí. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Fichero a firmar en una URL
	 * @return Firma XADES-T
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESTSignature signAttached (ACCVDeviceManager manager, URL document) throws LoadingObjectException, SignatureException, NoDocumentToSignException, XMLDocumentException {
		
		return signAttached(manager, document, null, null, null);

	}
	
	/**
	 * Realiza una firma XAdES-T attached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguirá la plantilla de Arangí. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Fichero a firmar en una URL
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param dof Información para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-T
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESTSignature signAttached (ACCVDeviceManager manager, URL document, 
			String digitalSignatureAlgorithm, XAdESDataObjectFormat dof,
			String[] claimedRoles) throws LoadingObjectException, SignatureException, NoDocumentToSignException, XMLDocumentException {
		
		try {
			return new XAdESTSignature (es.accv.arangi.base.signature.XAdESTSignature.signAttached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm,
				new URL (TimeStamp.URL_ACCV_TSA_SERVER), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv está bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-T attached (el documento se incluye en la firma). 
	 * 
	 * @param manager Dispositivo criptográfico que realizará la firma
	 * @param document Documento a firmar
	 * @param options Opciones para la firma
	 * @return Firma XADES-T
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 */
	public static XAdESTSignature signAttached (ACCVDeviceManager manager, IDocument document, 
			XAdESAttachedSignatureOptions options) throws XMLDocumentException, LoadingObjectException, SignatureException  {
		
		try {
			return new XAdESTSignature (es.accv.arangi.base.signature.XAdESTSignature.signAttached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, new TSAData(new URL (TimeStamp.URL_ACCV_TSA_SERVER)), options).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv está bien formada
			return null;
		}
	}
	
	/**
	 * La definición de las contrafirmas en XAdES puede observarse en el punto 7.2.4
	 * del estándar de la ETSI.<br><br>
	 * 
	 * Este método realiza una contrafirma para la última firma del XAdES. Es útil 
	 * cuando se sabe que el XAdES contiene sólo una firma.<br><br>
	 * 
	 * Como resultado el XAdES a la que hace referencia este objeto se modificará 
	 * para añadir la contrafirma.
	 * 
	 * @param manager Dispositivo criptográfico que realizará la contrafirma
	 * @throws LoadingObjectException No es posible obtener la clave privada o el
	 * 	certificado del alias
	 * @throws CounterSignatureException Errores durante el proceso de contrafirma
	 */
	public void counterSign (ACCVDeviceManager manager) throws LoadingObjectException, CounterSignatureException {
		counterSign(manager, null, null);
	}
	
	/**
	 * La definición de las contrafirmas en XAdES puede observarse en el punto 7.2.4
	 * del estándar de la ETSI.<br><br>
	 * 
	 * Este método realiza una contrafirma para la firma cuyo certificado se pasa
	 * en el parámetro 'signatureToCounterSignCertificate'. Es útil cuando se quiere
	 * contrafirmar un XAdES que contiene varias firmas. Para saber qué firma se
	 * desea contrafirmar se puede llamar primero a 
	 * {@link #getCertificates() getCertificates} para ver los certificados de cada
	 * una de las firmas que contiene el XAdES.<br><br>
	 * 
	 * Como resultado el XAdES a la que hace referencia este objeto se modificará 
	 * para añadir la contrafirma.
	 * 
	 * @param manager Dispositivo criptográfico que realizará la contrafirma
	 * @param signatureToCounterSignCertificate Certificado de la firma que se 
	 * 	contrafirmará
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @throws LoadingObjectException No es posible obtener la clave privada o el
	 * 	certificado del alias
	 * @throws CounterSignatureException Errores durante el proceso de contrafirma
	 */
	public void counterSign (ACCVDeviceManager manager, Certificate signatureToCounterSignCertificate,
			String digitalSignatureAlgorithm) throws LoadingObjectException, CounterSignatureException {
		
		try {
			counterSign((DeviceManager)manager, manager.getSignatureAlias(), signatureToCounterSignCertificate, 
					digitalSignatureAlgorithm, new URL (TimeStamp.URL_ACCV_TSA_SERVER));
		} catch (MalformedURLException e) {
			// No se va a dar, la URL es correcta
		}
	
	}
	
	/**
	 * Añade una Cofirma a la firma XAdES-T. Realizará una firma de las mismas características que 
	 * la primera que encuentre (attached o dettached).<br><br>
	 * 
	 * Si la firma es dettached y la referencia al documento que hay en la firma no
	 * es una URL será necesario usar el método {@link #coSign(ACCVDeviceManager, IDocument)}
	 * al que le proporcionaremos este documento.  
	 * 
	 * @param manager Dispositivo criptográfico que realizará la cofirma
	 * @throws SignatureNotFoundException No existe ninguna firma que cofirmar
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @throws HashingException Error realizando el hash del documento
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No ha sido posible parsear la firma XAdES o no se puede realizar la cofirma
	 * @throws NoCoincidentDocumentException El documento que se quiere firmar no se corresponde con el de
	 * 	la firma XAdES  
	 */
	public void coSign (ACCVDeviceManager manager)  throws SignatureNotFoundException, 
		NoDocumentToSignException, HashingException, LoadingObjectException, SignatureException, NoCoincidentDocumentException {
		coSign (manager, null, null);
	}
	
	
	/**
	 * Añade una Cofirma a la firma XAdES-T. Realizará una firma de las mismas características que 
	 * la primera que encuentre (attached o dettached).<br><br>
	 * 
	 * Este método es útil si la firma es dettached i la referencia al documento que hay en la firma no
	 * es una URL.  
	 * 
	 * @param manager Dispositivo criptográfico que realizará la cofirma
	 * @param signedDoc contenido a firmar. El mismo utilizado en la generación de las otras firmas.
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @throws SignatureNotFoundException No existe ninguna firma que cofirmar
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @throws HashingException Error realizando el hash del documento
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No ha sido posible parsear la firma XAdES o no se puede realizar la cofirma
	 * @throws NoCoincidentDocumentException El documento que se quiere firmar no se corresponde con el de
	 * 	la firma XAdES  
	 */
	public void coSign (ACCVDeviceManager manager, IDocument signedDoc, String digitalSignatureAlgorithm)  throws SignatureNotFoundException, 
		NoDocumentToSignException, HashingException, LoadingObjectException, SignatureException, NoCoincidentDocumentException {
		try {
			coSign ((DeviceManager)manager, manager.getSignatureAlias(), signedDoc, digitalSignatureAlgorithm, new URL (TimeStamp.URL_ACCV_TSA_SERVER));
		} catch (MalformedURLException e) {
			// No se va a dar, la URL es correcta
		}
	}
	
	
	/**
	 * Añade un sello de tiempos a la firma XAdES-BES. El servidor de Sellado de Tiempo 
	 * será el proporcionado por la Agencia de tecnologia y certificación electrónica (ACCV).
	 * 
	 * La firma XAdES-BES es necesario que sea attached. En el caso que no sea así deberá usar el 
	 * método {@link #completeToXAdEST (XAdESBESSignature, IDocument)}.
	 * 
	 * @param xadesBES firma XAdES-BES
	 * @return XAdES-T
	 * @throws HashingException Error obteniendo el hash del documento
	 * @throws SignatureException Error tratando el objeto firma o la firma XAdES-BES no es
	 * 	válida
	 * @throws XMLDocumentException Error completando el XML del XAdES-BES a XAdES-T
	 * @throws MalformedTimeStampException El sello de tiempos obtenido no está bien formado
	 * @throws ResponseTimeStampException No se ha podido obtener correctamente el sello de tiempos
	 */
	public static XAdESTSignature completeToXAdEST (XAdESBESSignature xadesBES) throws SignatureException, MalformedTimeStampException, ResponseTimeStampException, HashingException, XMLDocumentException  {
		return completeToXAdEST (xadesBES, null);
	}
	
	/**
	 * Añade un sello de tiempos a la firma XAdES-BES. El servidor de Sellado de Tiempo 
	 * será el proporcionado por la Agencia de tecnologia y certificación electrónica (ACCV).
	 * 
	 * @param xadesBES firma XAdES-BES
	 * @param document documento firmado en el XAdES-BES. Útil en el caso que el XAdES sea detached.
	 * @return XAdES-T
	 * @throws HashingException Error obteniendo el hash del documento
	 * @throws SignatureException Error tratando el objeto firma o la firma XAdES-BES no es
	 * 	válida
	 * @throws XMLDocumentException Error completando el XML del XAdES-BES a XAdES-T
	 * @throws MalformedTimeStampException El sello de tiempos obtenido no está bien formado
	 * @throws ResponseTimeStampException No se ha podido obtener correctamente el sello de tiempos
	 */
	public static XAdESTSignature completeToXAdEST (XAdESBESSignature xadesBES, IDocument document) throws SignatureException, MalformedTimeStampException, ResponseTimeStampException, HashingException, XMLDocumentException  {
		try {
			return new XAdESTSignature (es.accv.arangi.base.signature.XAdESTSignature.completeToXAdEST (xadesBES, document, 
					ArangiUtil.getACCVCaList(), new URL (TimeStamp.URL_ACCV_TSA_SERVER)).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv está bien formada
			return null;
		}
	}
	
	/**
	 * Comprueba que las firmas son correctas en firmas attached y sus certificados son válidos. Sólo
	 * serán validados los certificados tratados por Arangí.<br><br>
	 * 
	 * Sobre la validación de certificados hay que tener en cuenta:<br>
	 * <ul>
	 * 	<li>El sello de tiempos sólo será útil mientras el certificado 
	 *  no caduque. Después, al ser imposible obtener la información de revocación
	 *  para este certificado, este método devolverá siempre un resultado falso aunque el 
	 *  certificado fuera válido cuando se generó la firma .</li>
	 * </ul><br><br>
	 * 
	 * IMPORTANTE: este método sólo puede ser utilizado si la firma es attached (el documento
	 * que originó la firma se incluye en ésta). Si no es así utilizar el método con el mismo nombre 
	 * pero con el documento que originó la firma como parámetro.
	 * 
	 * @return Para cada certificado el resultado de comprobar si la firma es correcta y el certificado es
	 * 	válido
	 * @throws SignatureException Error tratando el objeto firma
	 */
	public ValidationResult[] isValid() throws SignatureException {
		
		return super.isValid (ArangiUtil.getACCVCaList());
	}
	
	/**
	 * Comprueba que las firmas son correctas y sus certificados son válidos. Sólo
	 * serán validados los certificados tratados por Arangí.<br><br> 
	 * 
	 * Sobre la validación de certificados hay que tener en cuenta:<br>
	 * <ul>
	 * 	<li>El sello de tiempos sólo será útil mientras el certificado 
	 *  no caduque. Después, al ser imposible obtener la información de revocación
	 *  para este certificado, este método devolverá siempre un resultado falso aunque el 
	 *  certificado fuera válido cuando se generó la firma .</li>
	 * </ul>
	 * 
	 * @param document documento firmado en el XAdES-T.
	 * @return Para cada certificado resultado de comprobar si la firma es correcta y el certificado es
	 * 	válido
	 * @throws SignatureException Error tratando el objeto firma
	 */
	public ValidationResult[] isValid(IDocument document) throws SignatureException {
		
		return super.isValid (document, ArangiUtil.getACCVCaList());
	}

	
}
