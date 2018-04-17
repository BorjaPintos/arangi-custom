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
import es.accv.arangi.base.exception.TimeStampException;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.device.LoadingObjectException;
import es.accv.arangi.base.exception.document.HashingException;
import es.accv.arangi.base.exception.signature.CounterSignatureException;
import es.accv.arangi.base.exception.signature.NoCoincidentDocumentException;
import es.accv.arangi.base.exception.signature.NoDocumentToSignException;
import es.accv.arangi.base.exception.signature.RetrieveOCSPException;
import es.accv.arangi.base.exception.signature.SignatureException;
import es.accv.arangi.base.exception.signature.SignatureNotFoundException;
import es.accv.arangi.base.exception.signature.XMLDocumentException;
import es.accv.arangi.base.exception.timestamp.MalformedTimeStampException;
import es.accv.arangi.base.exception.timestamp.ResponseTimeStampException;
import es.accv.arangi.base.signature.XAdESBESSignature;
import es.accv.arangi.base.signature.XAdESTSignature;
import es.accv.arangi.base.signature.util.TSAData;
import es.accv.arangi.base.signature.util.XAdESAttachedSignatureOptions;
import es.accv.arangi.base.signature.util.XAdESDataObjectFormat;
import es.accv.arangi.base.signature.util.XAdESDetachedSignatureOptions;
import es.accv.arangi.base.util.validation.ValidationResult;
import es.accv.arangi.device.ACCVDeviceManager;
import es.accv.arangi.timestamp.TimeStamp;
import es.accv.arangi.util.ArangiUtil;

/**
 * Clase que maneja firmas en formato XAdES-X-L de acuerdo al est�ndar 
 * <a href="http://uri.etsi.org/01903/v1.3.2/ts_101903v010302p.pdf" target="etsi">
 * ETSI TS 101 903</a><br><br>
 * 
 * El servidor de Sellado de Tiempo utilizado para generar XAdES-XL ser� el
 * proporcionado por la Agencia de tecnologia y certificaci�n electr�nica (ACCV): http://tss.accv.es:8318/tsa. 
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
 * //-- Genera una firma attached. El documento se guardar� en la firma en base64<br>
 * XAdESXLSignature signature1 = XAdESXLSignature.signAttached(manager, documentTexto);<br><br>
 * 
 * //-- Genera una firma detached que referencia al fichero en disco<br>
 * XAdESXLSignature signature2 = XAdESXLSignature.signDetached(manager, file);<br><br>
 * 
 * //-- Genera una firma detached que referencia a "2011/04/29/certificados/CER-2584665.pdf"<br>
 * XAdESXLSignature signature3 = XAdESXLSignature.signDetached(manager, file, "2011/04/29/certificados/CER-2584665.pdf");<br><br>
 * 
 * //-- Genera una firma detached que referencia al fichero ubicado en la URL<br>
 * XAdESXLSignature signature4 = XAdESXLSignature.signDetached(manager, url);<br><br>
 * 
 * //-- Genera una firma attached dentro del propio documento<br>
 * XAdESXLSignature signature5 = XAdESXLSignature.signAttached(manager, documentoXML, "titulo", "documento");<br><br>
 * </code>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class XAdESXLSignature extends es.accv.arangi.base.signature.XAdESXLSignature {

	/**
	 * Construye el objeto en base a un XML que tiene el formato
	 * XAdES-XL
	 * 
	 * @param xmlDocument Documento XML
	 */
	public XAdESXLSignature(Document xmlDocument) {
		super(xmlDocument);
	}

	/**
	 * Construye el objeto en base a un fichero XAdES-XL
	 * 
	 * @param xmlFile Fichero XAdES-XL
	 * @throws FileNotFoundException El fichero no existe
	 * @throws XMLDocumentException El fichero no parece un XML v�lido
	 */
	public XAdESXLSignature(File xmlFile) throws FileNotFoundException,
			XMLDocumentException {
		super(xmlFile);
	}
	
	/**
	 * Construye el objeto en base a un array de bytes.
	 * 
	 * @param signature Firma XAdES-XL
	 * @throws XMLDocumentException El fichero no parece un XML v�lido
	 */
	public XAdESXLSignature(byte[] signature) throws XMLDocumentException {
		super(signature);
	}

	/**
	 * Construye el objeto en base a un stream de lectura.
	 * 
	 * @param isSignature Firma XAdES-X-L
	 * @throws XMLDocumentException El fichero no parece un XML v�lido
	 */
	public XAdESXLSignature(InputStream isSignature) throws XMLDocumentException {
		super(isSignature);
	}


	/**
	 * Realiza una firma XAdES-XL detached (el fichero no se incluir� en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Fichero a firmar
	 * @return Firma XADES-XL
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESXLSignature signDetached (ACCVDeviceManager manager, File document) throws LoadingObjectException, SignatureException, NoDocumentToSignException {
		
		return signDetached(manager, document, null, null, null);
		
	}
	
	/**
	 * Realiza una firma XAdES-XL detached (el fichero no se incluir� en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Fichero a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param dof Informaci�n para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-XL
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESXLSignature signDetached (ACCVDeviceManager manager, File document, 
			String digitalSignatureAlgorithm, XAdESDataObjectFormat dof, String[] claimedRoles) throws LoadingObjectException, SignatureException, NoDocumentToSignException {
		
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.signDetached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm, 
					new URL (TimeStamp.URL_ACCV_TSA_SERVER), ArangiUtil.getACCVCaList(), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
		
	}
	
	/**
	 * Realiza una firma XAdES-XL detached (el fichero no se incluir� en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param urlDocument Documento a firmar. Se encuentra en una URL accesible.
	 * @return Firma XADES-XL
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESXLSignature signDetached (ACCVDeviceManager manager, URL urlDocument) throws LoadingObjectException, SignatureException, NoDocumentToSignException {
		
		return signDetached(manager, urlDocument, null, null, null);
		
	}
	
	/**
	 * Realiza una firma XAdES-XL detached (el fichero no se incluir� en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param urlDocument Documento a firmar. Se encuentra en una URL accesible.
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param dof Informaci�n para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-XL
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESXLSignature signDetached (ACCVDeviceManager manager, URL urlDocument, 
			String digitalSignatureAlgorithm, XAdESDataObjectFormat dof,
			String[] claimedRoles) throws LoadingObjectException, SignatureException, NoDocumentToSignException {
		
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.signDetached((DeviceManager) manager, 
					manager.getSignatureAlias(), urlDocument, digitalSignatureAlgorithm,
					new URL (TimeStamp.URL_ACCV_TSA_SERVER), ArangiUtil.getACCVCaList(), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-XL detached (el fichero no se incluir� en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Documento a firmar. 
	 * @param reference Referencia al documento a firmar (se incluir� en el XAdES-XL). Ej. Path al documento dentro de un gestor documental.
	 * @return Firma XADES-XL
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESXLSignature signDetached (ACCVDeviceManager manager, IDocument document, String reference) throws LoadingObjectException, SignatureException {
		
		return signDetached(manager, document, null, reference, null, null);
	
	}
	
	/**
	 * Realiza una firma XAdES-XL detached (el fichero no se incluir� en la firma). No completa los campos 
	 * no obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 
	 * 'signatureProductionPlace' y 'signerRole'.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Documento a firmar. 
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param reference Referencia al documento a firmar (se incluir� en el XAdES-XL). Ej. Path al documento dentro de un gestor documental.
	 * @param dof Informaci�n para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-XL
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signDetached(DeviceManager,IDocument,String,XAdESDetachedSignatureOptions) signDetached}
	 */
	public static XAdESXLSignature signDetached (ACCVDeviceManager manager, IDocument document, 
			String digitalSignatureAlgorithm, String reference,
			XAdESDataObjectFormat dof, String[] claimedRoles) throws LoadingObjectException, SignatureException {
		
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.signDetached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm, reference, new URL (TimeStamp.URL_ACCV_TSA_SERVER), ArangiUtil.getACCVCaList(), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-XL detached (el fichero no se incluir� en la firma). Si no
	 * se puede obtener la informaci�n de validaci�n mediante OCSP se producir� una
	 * excepci�n.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Documento a firmar. 
	 * @param reference Referencia al documento a firmar (se incluir� en el XAdES-XL). Ej. Path al documento dentro de un gestor documental.
	 * @param options Opciones para la firma
	 * @return Firma XADES-XL
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 */
	public static XAdESXLSignature signDetached (ACCVDeviceManager manager, IDocument document, 
			String reference, XAdESDetachedSignatureOptions options) throws LoadingObjectException, SignatureException {
		return signDetached(manager, document, reference, options, false);
	}
	
	/**
	 * Realiza una firma XAdES-XL detached (el fichero no se incluir� en la firma).<br><br>
	 * 
	 * Utilizar este m�todo si se desea permitir que se obtenga la informaci�n de validaci�n mediante 
	 * CRL (en caso de que no se pueda mediante OCSP). Cuidado con esta opci�n ya que las CRLs pueden 
	 * tener un tama�o considerable, por lo que la obtenci�n de la firma ser� m�s lenta y la misma firma
	 * puede acabar con un tama�o muy grande. 
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Documento a firmar. 
	 * @param reference Referencia al documento a firmar (se incluir� en el XAdES-XL). Ej. Path al documento dentro de un gestor documental.
	 * @param options Opciones para la firma
	 * @param allowCRLValidation Permitir generar la firma con CRLs si no se puede
	 *  realizar la validaci�n mediante OCSP
	 * @return Firma XADES-XL
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 */
	public static XAdESXLSignature signDetached (ACCVDeviceManager manager, IDocument document, 
			String reference, XAdESDetachedSignatureOptions options, boolean allowCRLValidation) 
					throws LoadingObjectException, SignatureException {
		
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.signDetached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, reference, new TSAData(new URL (TimeStamp.URL_ACCV_TSA_SERVER)), 
					ArangiUtil.getACCVCaList(), options, allowCRLValidation).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-XL attached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.
	 * 
	 * Si el documento es un XML y los par�metros <code>idToSign</code> y <code>signatureParent</code>
	 * no son nulos la firma y los campos propios de XAdES se a�adir�n al XML. En caso contrario el fichero 
	 * XAdES resultante seguir� la plantilla de Arang�, por ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Documento a firmar
	 * @param idToSign Valor del atributo 'ID' que indica lo que se firmar� dentro del documento. Si tiene 
	 *  valor nulo el XML de la firma tendr� el formato por defecto de las firmas XAdES de Arang�.
	 * @param signatureParent Nombre del tag que ser� el padre de los nodos de firma. Si tiene valor nulo
	 * 	la firma colgar� del nodo ra�z.
	 * @return Firma XADES-XL
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESXLSignature signAttached (ACCVDeviceManager manager, IDocument document, String idToSign,
			String signatureParent) throws XMLDocumentException, LoadingObjectException, SignatureException  {
		
		return signAttached(manager, document, null, idToSign, signatureParent, null, null);
		
	}
	
	/**
	 * Realiza una firma XAdES-XL attached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.
	 * 
	 * Si el documento es un XML y los par�metros <code>idToSign</code> y <code>signatureParent</code>
	 * no son nulos la firma y los campos propios de XAdES se a�adir�n al XML. En caso contrario el fichero 
	 * XAdES resultante seguir� la plantilla de Arang�, por ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Documento a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param idToSign Valor del atributo 'ID' que indica lo que se firmar� dentro del documento. Si tiene 
	 *  valor nulo el XML de la firma tendr� el formato por defecto de las firmas XAdES de Arang�.
	 * @param signatureParent Nombre del tag que ser� el padre de los nodos de firma. Si tiene valor nulo
	 * 	la firma colgar� del nodo ra�z.
	 * @param dof Informaci�n para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-XL
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESXLSignature signAttached (ACCVDeviceManager manager, IDocument document, 
			String digitalSignatureAlgorithm, String idToSign,
			String signatureParent, XAdESDataObjectFormat dof, String[] claimedRoles) throws XMLDocumentException, LoadingObjectException, SignatureException  {
		
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.signAttached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm, idToSign, 
					signatureParent, new URL (TimeStamp.URL_ACCV_TSA_SERVER), ArangiUtil.getACCVCaList(), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
		
	}
	
	/**
	 * Realiza una firma XAdES-XL attached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguir� la plantilla de Arang�. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Documento a firmar
	 * @return Firma XADES-XL
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESXLSignature signAttached (ACCVDeviceManager manager, IDocument document) throws XMLDocumentException, LoadingObjectException, SignatureException  {
		
		return signAttached(manager, document, (String)null, null);
		
	}
	
	/**
	 * Realiza una firma XAdES-XL attached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguir� la plantilla de Arang�. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Documento a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param dof Informaci�n para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-XL
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESXLSignature signAttached (ACCVDeviceManager manager, IDocument document, 
			String digitalSignatureAlgorithm, XAdESDataObjectFormat dof,
			String[] claimedRoles) throws XMLDocumentException, LoadingObjectException, SignatureException  {
		
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.signAttached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm, 
					new URL (TimeStamp.URL_ACCV_TSA_SERVER), ArangiUtil.getACCVCaList(), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-XL atached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguir� la plantilla de Arang�. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Fichero a firmar
	 * @return Firma XADES-XL
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESXLSignature signAttached (ACCVDeviceManager manager, File document) throws LoadingObjectException, SignatureException, NoDocumentToSignException, XMLDocumentException {
		
		return signAttached(manager, document, null, null, null);
		
	}

	/**
	 * Realiza una firma XAdES-XL atached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguir� la plantilla de Arang�. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Fichero a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param dof Informaci�n para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-XL
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESXLSignature signAttached (ACCVDeviceManager manager, File document, 
			String digitalSignatureAlgorithm, XAdESDataObjectFormat dof,
			String[] claimedRoles) throws LoadingObjectException, SignatureException, NoDocumentToSignException, XMLDocumentException {
		
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.signAttached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm, 
					new URL (TimeStamp.URL_ACCV_TSA_SERVER), ArangiUtil.getACCVCaList(), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
	}

	/**
	 * Realiza una firma XAdES-XL atached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguir� la plantilla de Arang�. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Fichero a firmar (se encuentra en una URL accesible)
	 * @return Firma XADES-XL
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESXLSignature signAttached (ACCVDeviceManager manager, URL document) throws LoadingObjectException, SignatureException, NoDocumentToSignException, XMLDocumentException {

		return signAttached(manager, document, null, null, null);
		
	}
	
	/**
	 * Realiza una firma XAdES-XL atached (el documento se incluye en la firma). No completa los campos no 
	 * obligatorios del tag 'SignedSignatureProperties':'signaturePolicyIdentifier', 'signatureProductionPlace' 
	 * y 'signerRole'.<br><br>
	 * 
	 * El fichero XAdES seguir� la plantilla de Arang�. Ejemplo:<br>
	 * <code>
	 * 	&lt;arangi-xades&gt;<br>
	 *  &nbsp;&nbsp;&lt;document&gt;...&lt;/document&gt;<br>
	 *  &nbsp;&nbsp;&lt;ds:Signature&gt;...&lt;/ds:Signature&gt;<br>
	 * 	&lt;/arangi-xades&gt;<br>
	 * </code>
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Fichero a firmar (se encuentra en una URL accesible)
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param dof Informaci�n para construir el tag DataObjectFormat (puede ser null)
	 * @param claimedRoles Roles de la firma (puede ser null)
	 * @return Firma XADES-XL
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 * @deprecated Usar {@link #signAttached(DeviceManager,IDocument,XAdESAttachedSignatureOptions) signAttached}
	 */
	public static XAdESXLSignature signAttached (ACCVDeviceManager manager, URL document, 
			String digitalSignatureAlgorithm, XAdESDataObjectFormat dof,
			String[] claimedRoles) throws LoadingObjectException, SignatureException, NoDocumentToSignException, XMLDocumentException {
		
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.signAttached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, digitalSignatureAlgorithm, 
					new URL (TimeStamp.URL_ACCV_TSA_SERVER), ArangiUtil.getACCVCaList(), dof, claimedRoles).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
	}
	
	/**
	 * Realiza una firma XAdES-XL attached (el documento se incluye en la firma). Si no
	 * se puede obtener la informaci�n de validaci�n mediante OCSP se producir� una
	 * excepci�n.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Documento a firmar
	 * @param options Opciones para la firma
	 * @return Firma XADES-XL
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 */
	public static XAdESXLSignature signAttached (ACCVDeviceManager manager, IDocument document, 
			XAdESAttachedSignatureOptions options) throws XMLDocumentException, LoadingObjectException, SignatureException  {
		return signAttached(manager, document, options, false);
	}
	
	/**
	 * Realiza una firma XAdES-XL attached (el documento se incluye en la firma).   <br><br>
	 * 
	 * Utilizar este m�todo si se desea permitir que se obtenga la informaci�n de validaci�n mediante 
	 * CRL (en caso de que no se pueda mediante OCSP). Cuidado con esta opci�n ya que las CRLs pueden 
	 * tener un tama�o considerable, por lo que la obtenci�n de la firma ser� m�s lenta y la misma firma
	 * puede acabar con un tama�o muy grande.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la firma
	 * @param document Documento a firmar
	 * @param options Opciones para la firma
	 * @param allowCRLValidation Permitir generar la firma con CRLs si no se puede
	 *  realizar la validaci�n mediante OCSP
	 * @return Firma XADES-XL
	 * @throws XMLDocumentException Error montando el fichero XML
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No se puede realizar la firma
	 */
	public static XAdESXLSignature signAttached (ACCVDeviceManager manager, IDocument document, 
			XAdESAttachedSignatureOptions options, boolean allowCRLValidation) throws XMLDocumentException, LoadingObjectException, SignatureException  {
		
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.signAttached((DeviceManager) manager, 
					manager.getSignatureAlias(), document, new TSAData(new URL (TimeStamp.URL_ACCV_TSA_SERVER)), 
					ArangiUtil.getACCVCaList(), options, allowCRLValidation).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
	}
	
	/**
	 * La definici�n de las contrafirmas en XAdES puede observarse en el punto 7.2.4
	 * del est�ndar de la ETSI.<br><br>
	 * 
	 * Este m�todo realiza una contrafirma para la �ltima firma del XAdES. Es �til 
	 * cuando se sabe que el XAdES contiene s�lo una firma.<br><br>
	 * 
	 * Como resultado el XAdES a la que hace referencia este objeto se modificar� 
	 * para a�adir la contrafirma.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la contrafirma
	 * @throws LoadingObjectException No es posible obtener la clave privada o el
	 * 	certificado del alias
	 * @throws CounterSignatureException Errores durante el proceso de contrafirma
	 */
	public void counterSign (ACCVDeviceManager manager) throws LoadingObjectException, CounterSignatureException {
		counterSign(manager, null, null);
	}
	
	/**
	 * La definici�n de las contrafirmas en XAdES puede observarse en el punto 7.2.4
	 * del est�ndar de la ETSI.<br><br>
	 * 
	 * Este m�todo realiza una contrafirma para la firma cuyo certificado se pasa
	 * en el par�metro 'signatureToCounterSignCertificate'. Es �til cuando se quiere
	 * contrafirmar un XAdES que contiene varias firmas. Para saber qu� firma se
	 * desea contrafirmar se puede llamar primero a 
	 * {@link #getCertificates() getCertificates} para ver los certificados de cada
	 * una de las firmas que contiene el XAdES.<br><br>
	 * 
	 * Como resultado el XAdES a la que hace referencia este objeto se modificar� 
	 * para a�adir la contrafirma.
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la contrafirma
	 * @param signatureToCounterSignCertificate Certificado de la firma que se 
	 * 	contrafirmar�
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @throws LoadingObjectException No es posible obtener la clave privada o el
	 * 	certificado del alias
	 * @throws CounterSignatureException Errores durante el proceso de contrafirma
	 */
	public void counterSign (ACCVDeviceManager manager, Certificate signatureToCounterSignCertificate,
			String digitalSignatureAlgorithm) throws LoadingObjectException, CounterSignatureException {
		
		try {
			counterSign((DeviceManager)manager, manager.getSignatureAlias(), signatureToCounterSignCertificate, 
					digitalSignatureAlgorithm, new URL (TimeStamp.URL_ACCV_TSA_SERVER), ArangiUtil.getACCVCaList());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL es correcta
		}
	
	}
	
	/**
	 * A�ade una Cofirma a la firma XAdES-XL. Realizar� una firma de las mismas caracter�sticas que 
	 * la primera que encuentre (attached o dettached).<br><br>
	 * 
	 * Si la firma es dettached i la referencia al documento que hay en la firma no
	 * es una URL ser� necesario usar el m�todo {@link #coSign(ACCVDeviceManager, IDocument)}
	 * al que le proporcionaremos este documento.  
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la cofirma
	 * @throws SignatureNotFoundException No existe ninguna firma que cofirmar
	 * @throws NoDocumentToSignException El fichero a firmar no existe o es nulo
	 * @throws HashingException Error realizando el hash del documento
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada o el certificado usados
	 *  para realizar la firma
	 * @throws SignatureException No ha sido posible parsear la firma XAdES o no se puede realizar la cofirma
	 * @throws NoCoincidentDocumentException El documento que se quiere firmar no se corresponde con el de
	 * 	la firma XAdES  
	 */
	public void coSign (ACCVDeviceManager manager) throws SignatureNotFoundException, 
		NoDocumentToSignException, HashingException, LoadingObjectException, SignatureException, NoCoincidentDocumentException {
		
		coSign (manager, null, null);
	}
	
	
	/**
	 * A�ade una Cofirma a la firma XAdES-XL. Realizar� una firma de las mismas caracter�sticas que 
	 * la primera que encuentre (attached o dettached).<br><br>
	 * 
	 * Este m�todo es �til si la firma es dettached i la referencia al documento que hay en la firma no
	 * es una URL.  
	 * 
	 * @param manager Dispositivo criptogr�fico que realizar� la cofirma
	 * @param signedDoc contenido a firmar. El mismo utilizado en la generaci�n de las otras firmas
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
	public void coSign (ACCVDeviceManager manager, IDocument signedDoc, String digitalSignatureAlgorithm) throws SignatureNotFoundException, 
		NoDocumentToSignException, HashingException, LoadingObjectException, SignatureException, NoCoincidentDocumentException {
		try {
			coSign((DeviceManager)manager, manager.getSignatureAlias(), signedDoc, 
					digitalSignatureAlgorithm, new URL (TimeStamp.URL_ACCV_TSA_SERVER), ArangiUtil.getACCVCaList());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL es correcta
		}
	}
	
	/**
	 * A�ade lo que falta para completar el XAdES-T a XAdES-X-L. La firma tiene que ser attached. Si no es as� es necesario
	 * usar {@link #completeToXAdESXL (XAdESTSignature, IDocument)}.
	 * 
	 * @param xadesT Firma XAdES-T
	 * @return Firma XAdES-X-L
	 * @throws NormalizeCertificateException Alguno de los certificados no puede ser 
	 * 	normalizado al formato reconocido por el proveedor criptogr�fico de Arang� o su 
	 * 	firma no es correcta o no puede ser analizada
	 * @throws SignatureException Error tratando el objeto firma o la firma XAdES-T no es
	 * 	v�lida
	 * @throws RetrieveOCSPException Error obteniendo las respuestas OCSP
	 * @throws XMLDocumentException Error completando el XML del XAdES-T a XAdES-X-L
	 */
	public static XAdESXLSignature completeToXAdESXL (XAdESTSignature xadesT) throws SignatureException, NormalizeCertificateException, RetrieveOCSPException, XMLDocumentException {
		return completeToXAdESXL (xadesT, null);
	}
	
	/**
	 * A�ade lo que falta para completar el XAdES-T a XAdES-X-L
	 * 
	 * @param xadesT Firma XAdES-T
	 * @param document documento firmado en el XAdES-T. �til en el caso que el XAdES sea detached.
	 * @return Firma XAdES-X-L
	 * @throws NormalizeCertificateException Alguno de los certificados no puede ser 
	 * 	normalizado al formato reconocido por el proveedor criptogr�fico de Arang� o su 
	 * 	firma no es correcta o no puede ser analizada
	 * @throws SignatureException Error tratando el objeto firma o la firma XAdES-T no es
	 * 	v�lida
	 * @throws RetrieveOCSPException Error obteniendo las respuestas OCSP
	 * @throws XMLDocumentException Error completando el XML del XAdES-T a XAdES-X-L
	 */
	public static XAdESXLSignature completeToXAdESXL (XAdESTSignature xadesT, IDocument document) throws SignatureException, NormalizeCertificateException, RetrieveOCSPException, XMLDocumentException {
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.completeToXAdESXL (xadesT, document,
					ArangiUtil.getACCVCaList(), new URL (TimeStamp.URL_ACCV_TSA_SERVER)).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
	}
	
	/**
	 * A�ade lo que falta para completar el XAdES-BES a XAdES-X-L. La firma tiene que ser attached. Si no es as� es necesario
	 * usar {@link #completeToXAdESXL (XAdESBESSignature, IDocument)}.
	 * 
	 * @param xadesBES Firma XAdES-BES
	 * @return Firma XAdES-X-L
	 * @throws ResponseTimeStampException No se ha podido obtener correctamente el sello de tiempos
	 * @throws MalformedTimeStampException El sello de tiempos obtenido no est� bien formado
	 * @throws NormalizeCertificateException Alguno de los certificados no puede ser 
	 * 	normalizado al formato reconocido por el proveedor criptogr�fico de Arang� o su 
	 * 	firma no es correcta o no puede ser analizada
	 * @throws SignatureException Error tratando el objeto firma o la firma XAdES-T no es
	 * 	v�lida
	 * @throws HashingException Error obteniendo el hash del documento
	 * @throws RetrieveOCSPException Error obteniendo las respuestas OCSP
	 * @throws XMLDocumentException Error completando el XML del XAdES-T a XAdES-X-L
	 */
	public static XAdESXLSignature completeToXAdESXL (XAdESBESSignature xadesBES) throws SignatureException, MalformedTimeStampException, ResponseTimeStampException, HashingException, XMLDocumentException, NormalizeCertificateException, RetrieveOCSPException {
		return completeToXAdESXL (xadesBES, null);
	}
	
	/**
	 * A�ade lo que falta para completar el XAdES-BES a XAdES-X-L
	 * 
	 * @param xadesBES Firma XAdES-BES
	 * @param document documento firmado en el XAdES-T. �til en el caso que el XAdES sea detached.
	 * @return Firma XAdES-X-L
	 * @throws ResponseTimeStampException No se ha podido obtener correctamente el sello de tiempos
	 * @throws MalformedTimeStampException El sello de tiempos obtenido no est� bien formado
	 * @throws NormalizeCertificateException Alguno de los certificados no puede ser 
	 * 	normalizado al formato reconocido por el proveedor criptogr�fico de Arang� o su 
	 * 	firma no es correcta o no puede ser analizada
	 * @throws SignatureException Error tratando el objeto firma o la firma XAdES-T no es
	 * 	v�lida
	 * @throws HashingException Error obteniendo el hash del documento
	 * @throws RetrieveOCSPException Error obteniendo las respuestas OCSP
	 * @throws XMLDocumentException Error completando el XML del XAdES-T a XAdES-X-L
	 */
	public static XAdESXLSignature completeToXAdESXL (XAdESBESSignature xadesBES, IDocument document) throws SignatureException, MalformedTimeStampException, ResponseTimeStampException, HashingException, XMLDocumentException, NormalizeCertificateException, RetrieveOCSPException {
		try {
			return new XAdESXLSignature (es.accv.arangi.base.signature.XAdESXLSignature.completeToXAdESXL (xadesBES, document, 
					ArangiUtil.getACCVCaList(), new URL (TimeStamp.URL_ACCV_TSA_SERVER)).getDOM());
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
			return null;
		}
	}
	
	/**
	 * Comprueba que las firmas son correctas en firmas attached y sus certificados son v�lidos. S�lo
	 * ser�n validados los certificados tratados por Arang�.<br><br>
	 * 
	 * IMPORTANTE: este m�todo s�lo puede ser utilizado si la firma es attached (el documento
	 * que origin� la firma se incluye en �sta). Si no es as� utilizar el m�todo con el mismo nombre 
	 * pero con el documento que origin� la firma como par�metro.
	 * 
	 * @return Para cada certificado el resultado de comprobar si la firma es correcta y el certificado es
	 * 	v�lido
	 * @throws SignatureException Error tratando el objeto firma
	 */
	public ValidationResult[] isValid() throws SignatureException {
		
		return super.isValid (ArangiUtil.getACCVCaList());
	}
	
	/**
	 * Comprueba que las firmas son correctas y sus certificados son v�lidos. S�lo
	 * ser�n validados los certificados tratados por Arang�.<br><br> 
	 *
	 * @param document documento firmado en el XAdES-XL.
	 * @return Para cada certificado resultado de comprobar si la firma es correcta y el certificado es
	 * 	v�lido
	 * @throws SignatureException Error tratando el objeto firma
	 */
	public ValidationResult[] isValid(IDocument document) throws SignatureException {
		
		return super.isValid (document, ArangiUtil.getACCVCaList());
	}

	/**
	 * A�ade un sello de tiempos de archivado a todas las firmas incluidas en este
	 * fichero XAdES-X-L (convirti�ndolo, si no lo era ya, en un XAdES-A).
	 * 
	 * @throws SignatureException Error tratando con las firmas contenidas en el XAdES-X-L
	 * @throws TimeStampException Error obteniendo el sello de tiempos
	 * @throws XMLDocumentException Error modificando el XML para a�adirle los nuevos sellos
	 * 	de tiempos
	 */
	public void addArchiveTimeStamp() throws SignatureException,
			TimeStampException, XMLDocumentException {
		try {
			super.addArchiveTimeStamp(new URL (TimeStamp.URL_ACCV_TSA_SERVER));
		} catch (MalformedURLException e) {
			// No se va a dar, la URL de la tsa de la accv est� bien formada
		}
	}
	
}
