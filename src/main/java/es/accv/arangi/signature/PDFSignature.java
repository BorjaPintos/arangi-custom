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
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import es.accv.arangi.base.device.DeviceManager;
import es.accv.arangi.base.document.IDocument;
import es.accv.arangi.base.exception.certificate.CertificateCANotFoundException;
import es.accv.arangi.base.exception.certificate.NormalizeCertificateException;
import es.accv.arangi.base.exception.device.AliasNotFoundException;
import es.accv.arangi.base.exception.device.LoadingObjectException;
import es.accv.arangi.base.exception.document.HashingException;
import es.accv.arangi.base.exception.signature.AlgorithmNotSuitableException;
import es.accv.arangi.base.exception.signature.InvalidCertificateException;
import es.accv.arangi.base.exception.signature.PDFDocumentException;
import es.accv.arangi.base.exception.signature.SignatureException;
import es.accv.arangi.base.exception.signature.SignatureNotFoundException;
import es.accv.arangi.base.util.validation.ValidationResult;
import es.accv.arangi.device.ACCVDeviceManager;
import es.accv.arangi.timestamp.TimeStamp;
import es.accv.arangi.util.ArangiUtil;

/**
 * Clase para manejar firmas en PDF según la norma 
 * <a href="http://www.iso.org/iso/catalogue_detail.htm?csnumber=51502" target="estandar">ISO 32000-1</a><br><br>
 * 
 * Para evitar problemas de saturación de memoria con ficheros PDF muy grandes,
 * esta clase siempre trabajará sobre un objeto java.io.File. Si el objeto no se 
 * inicializa con un fichero se creará un archivo temporal en la carpeta temporal 
 * de Arangi: {@link #getArangiTemporalFolder() getArangiTemporalFolder}.
 * 
 * Existen dos métodos para obtener una firma PDF, dependiendo de si se desea 
 * una firma visible o invisible. En el caso de las firmas visibles hay que proporcionar 
 * al método las coordenadas de las esquinas inferior izquierda y superior derecha, así 
 * como el número de página donde se desea ubicar la firma. También es posible asociar
 * una imagen a la firma.<br><br>
 * 
 * <code>
 * KeyStoreManager manager = new KeyStoreManager (...,...);<br>
 * ByteArrayDocument documentPDF = new ByteArrayDocument (...);<br><br>
 * 
 * //-- Firma invisible<br>
 * PDFSignature signatureInv = PDFSignature.sign (new ACCVDeviceManager[] {manager},documentPDF, "Porque quiero firmarlo");<br><br>
 * 
 * //-- Firma visible<br>
 * PDFSignature signatureVis = PDFSignature.sign (new ACCVDeviceManager[] {manager},documentPDF, "Porque quiero firmarlo",
 *      true, Util.readStream(ClassLoader.getSystemResourceAsStream("signature/chip.gif")), 100, 100, 300, 200, 1);<br><br>
 * </code>
 * 
 * En la página 1 de la segunda firma, en la ubicación indicada por las coordenadas, se 
 * verá la imagen chip.gif como una firma realizada sobre el PDF.El primer parámetro del
 * método de firma es un array de managers, ya que es posible realizar varias firmas a 
 * la vez.<br><br>
 * 
 * Cabe la posibilidad de crear firmas sin sello de tiempo. Para ello se debe utilizar alguno 
 * de los métodos signWithoutTimeStamp.<br>
 * 
 * @author <a href="mailto:jgutierrez@accv.es">José M Gutiérrez</a>
 */
public class PDFSignature extends es.accv.arangi.base.signature.PDFSignature {

	/**
	 * Inicializa el objeto con el contenido de un fichero PDF firmado.
	 * 
	 * @param pdfContentBytes Array de bytes con el contenido del fichero PDF firmado
	 * @throws PDFDocumentException El fichero no es un PDF correcto o bien no puede 
	 * 	ser leído
	 * @throws SignatureNotFoundException El fichero es un PDF pero no está firmado
	 * @throws IOException No se puede crear el fichero temporal
	 */
	public PDFSignature(byte[] pdfContentBytes) throws PDFDocumentException,
			SignatureNotFoundException, IOException {
		super(pdfContentBytes);
	}

	/**
	 * Inicializa el objeto con un fichero PDF firmado.
	 * 
	 * @param pdfFile Fichero PDF firmado
	 * @throws PDFDocumentException El fichero no es un PDF correcto o bien no puede 
	 * 	ser leído
	 * @throws SignatureNotFoundException El fichero es un PDF pero no está firmado
	 */
	public PDFSignature(File pdfFile) throws PDFDocumentException,
			SignatureNotFoundException {
		super(pdfFile);
	}

	/**
	 * Inicializa el objeto con un documento que debe contener un fichero PDF firmado.
	 * 
	 * @param document Documento con el contenido del fichero PDF firmado
	 * @throws PDFDocumentException El fichero no es un PDF correcto o bien no puede 
	 * 	ser leído
	 * @throws SignatureNotFoundException El fichero es un PDF pero no está firmado
	 * @throws IOException No se puede crear el fichero temporal
	 */
	public PDFSignature(IDocument document) throws PDFDocumentException,
			SignatureNotFoundException, IOException {
		super(document);
	}

	/**
	 * Inicializa el objeto con un stream de lectura al contenido de un fichero PDF firmado.
	 * 
	 * @param streamPDF Stream de lectura al contenido del fichero PDF firmado
	 * @throws PDFDocumentException El fichero no es un PDF correcto o bien no puede 
	 * 	ser leído
	 * @throws SignatureNotFoundException El fichero es un PDF pero no está firmado
	 * @throws IOException No se puede crear el fichero temporal
	 */
	public PDFSignature(InputStream streamPDF) throws PDFDocumentException,
			SignatureNotFoundException, IOException {
		super(streamPDF);
	}

	/*
	 * Sólo para pasar de una firma base a una de arangi
	 */
	private PDFSignature(es.accv.arangi.base.signature.PDFSignature signature) {
		super(signature);
	}

	/**
	 * Obtiene un objeto {@link PDFSignature PDFSignature} tras firmar un documento PDF.
	 * La firma es invisible.
	 * 
	 * @param managers Dispositivos criptográfico que realizarán la firma
	 * @param pdfDocument Documento PDF a firmar
	 * @param reason Texto que aparecerá junto a la firma como razón. Si se pasa un valor
	 * 	nulo se escribirá un texto por defecto.
	 * @return Documento PDF firmado, con sello de tiempos
	 * @throws AliasNotFoundException El alias donde se encuentra la clave privada usada para
	 * 	realizar la firma no existe
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws PDFDocumentException El documento no es un fichero PDF o es un PDF mal formado
	 * @throws SignatureException No se puede realizar la firma
	 * @throws HashingException Excepción obteniendo el hash que será sellado por la TSA
	 * @throws CertificateCANotFoundException La lista de certificado de CA no contiene el 
	 * 	emisor del certificado de firma o existe pero tiene un formato no normalizable por 
	 * 	el proveedor criptográfico de Arangi
	 * @throws InvalidCertificateException El certificado con el que se firma está revocado
	 */
	public static PDFSignature sign (ACCVDeviceManager managers[], IDocument pdfDocument, String reason) throws AliasNotFoundException, 
		LoadingObjectException, PDFDocumentException, SignatureException, HashingException, CertificateCANotFoundException, 
		InvalidCertificateException {
		
		try {
			return sign (managers, pdfDocument, null, reason, false, null, -1, -1, -1, -1, 0);
		} catch (AlgorithmNotSuitableException e) {
			throw new SignatureException("El algoritmo por defecto no debería provocar este error", e);
		}
	}
	
	/**
	 * Obtiene un objeto {@link PDFSignature PDFSignature} tras firmar un documento PDF.<br><br>
	 * 
	 * Si la firma es visible se le puede asociar una imagen. El punto 0,0 de la página 
	 * se encuentra en la esquina inferior izquierda de la misma. Un página tiene 
	 * aproximadamente unas dimensiones de 580x850. 
	 * 
	 * @param managers Dispositivos criptográfico que realizarán la firma
	 * @param pdfDocument Documento PDF a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param reason Texto que aparecerá junto a la firma como razón. Si se pasa un valor
	 * 	nulo se escribirá un texto por defecto.
	 * @param isVisible Si tiene un valor cierto se creará una firma visible.
	 * @param image Imagen de la firma. Puede tener un valor nulo.
	 * @param llX Posición X de la esquina inferior izquierda de la firma en la página (caso de ser visible)
	 * @param llY Posición Y de la esquina inferior izquierda de la firma en la página (caso de ser visible) 
	 * @param urX Posición X de la esquina superior derecha de la firma en la página (caso de ser visible)
	 * @param urY Posición Y de la esquina superior derecha de la firma en la página (caso de ser visible)
	 * @param page Página en la que se situará la firma si ésta es visible (1 es la primera página)
	 * @return Documento PDF firmado, con sello de tiempos
	 * @throws AliasNotFoundException El alias donde se encuentra la clave privada usada para
	 * 	realizar la firma no existe
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws PDFDocumentException El documento no es un fichero PDF o es un PDF mal formado
	 * @throws SignatureException No se puede realizar la firma
	 * @throws HashingException Excepción obteniendo el hash que será sellado por la TSA
	 * @throws CertificateCANotFoundException La lista de certificado de CA no contiene el 
	 * 	emisor del certificado de firma o existe pero tiene un formato no normalizable por 
	 * 	el proveedor criptográfico de Arangi
	 * @throws InvalidCertificateException El certificado con el que se firma está revocado
	 * @throws AlgorithmNotSuitableException El algoritmo de firma pasado no sirve para realizar la firma
	 */
	public static PDFSignature sign (ACCVDeviceManager[] managers, IDocument pdfDocument, 
			String digitalSignatureAlgorithm, String reason, boolean isVisible, byte[] image, 
			float llX, float llY, float urX, float urY, int page) throws AliasNotFoundException, LoadingObjectException, PDFDocumentException, 
			SignatureException, HashingException, CertificateCANotFoundException, InvalidCertificateException, AlgorithmNotSuitableException {
		
		return sign(managers, pdfDocument, digitalSignatureAlgorithm, reason, isVisible, image, llX, llY, urX, urY, page, true);
	}
	
	/**
	 * Obtiene un objeto {@link PDFSignature PDFSignature} tras firmar un documento PDF.
	 * La firma es invisible. La firma no contiene sello de tiempos.
	 * 
	 * @param managers Dispositivos criptográfico que realizarán la firma
	 * @param pdfDocument Documento PDF a firmar
	 * @param reason Texto que aparecerá junto a la firma como razón. Si se pasa un valor
	 * 	nulo se escribirá un texto por defecto.
	 * @return Documento PDF firmado, con sello de tiempos
	 * @throws AliasNotFoundException El alias donde se encuentra la clave privada usada para
	 * 	realizar la firma no existe
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws PDFDocumentException El documento no es un fichero PDF o es un PDF mal formado
	 * @throws SignatureException No se puede realizar la firma
	 * @throws HashingException Excepción obteniendo el hash que será sellado por la TSA
	 * @throws CertificateCANotFoundException La lista de certificado de CA no contiene el 
	 * 	emisor del certificado de firma o existe pero tiene un formato no normalizable por 
	 * 	el proveedor criptográfico de Arangi
	 * @throws InvalidCertificateException El certificado con el que se firma está revocado
	 */
	public static PDFSignature signWithoutTimeStamp (ACCVDeviceManager managers[], IDocument pdfDocument, String reason) throws AliasNotFoundException, 
		LoadingObjectException, PDFDocumentException, SignatureException, HashingException, CertificateCANotFoundException, 
		InvalidCertificateException {
		
		try {
			return signWithoutTimeStamp (managers, pdfDocument, null, reason, false, null, -1, -1, -1, -1, 0);
		} catch (AlgorithmNotSuitableException e) {
			throw new SignatureException("El algoritmo por defecto no debería provocar este error", e);
		}
	}
	
	/**
	 * Obtiene un objeto {@link PDFSignature PDFSignature} tras firmar un documento PDF.<br><br>
	 * 
	 * Si la firma es visible se le puede asociar una imagen. El punto 0,0 de la página 
	 * se encuentra en la esquina inferior izquierda de la misma. Un página tiene 
	 * aproximadamente unas dimensiones de 580x850. <br><br>
	 * 
	 * La firma no contiene sello de tiempos.
	 * 
	 * @param managers Dispositivos criptográfico que realizarán la firma
	 * @param pdfDocument Documento PDF a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param reason Texto que aparecerá junto a la firma como razón. Si se pasa un valor
	 * 	nulo se escribirá un texto por defecto.
	 * @param isVisible Si tiene un valor cierto se creará una firma visible.
	 * @param image Imagen de la firma. Puede tener un valor nulo.
	 * @param llX Posición X de la esquina inferior izquierda de la firma en la página (caso de ser visible)
	 * @param llY Posición Y de la esquina inferior izquierda de la firma en la página (caso de ser visible) 
	 * @param urX Posición X de la esquina superior derecha de la firma en la página (caso de ser visible)
	 * @param urY Posición Y de la esquina superior derecha de la firma en la página (caso de ser visible)
	 * @param page Página en la que se situará la firma si ésta es visible (1 es la primera página)
	 * @return Documento PDF firmado, con sello de tiempos
	 * @throws AliasNotFoundException El alias donde se encuentra la clave privada usada para
	 * 	realizar la firma no existe
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws PDFDocumentException El documento no es un fichero PDF o es un PDF mal formado
	 * @throws SignatureException No se puede realizar la firma
	 * @throws HashingException Excepción obteniendo el hash que será sellado por la TSA
	 * @throws CertificateCANotFoundException La lista de certificado de CA no contiene el 
	 * 	emisor del certificado de firma o existe pero tiene un formato no normalizable por 
	 * 	el proveedor criptográfico de Arangi
	 * @throws InvalidCertificateException El certificado con el que se firma está revocado
	 * @throws AlgorithmNotSuitableException El algoritmo de firma pasado no sirve para realizar la firma
	 */
	public static PDFSignature signWithoutTimeStamp (ACCVDeviceManager[] managers, IDocument pdfDocument, 
			String digitalSignatureAlgorithm, String reason, boolean isVisible, byte[] image, 
			float llX, float llY, float urX, float urY, int page) throws AliasNotFoundException, LoadingObjectException, PDFDocumentException, 
			SignatureException, HashingException, CertificateCANotFoundException, InvalidCertificateException, AlgorithmNotSuitableException {
		
		return sign(managers, pdfDocument, digitalSignatureAlgorithm, reason, isVisible, image, llX, llY, urX, urY, page, false);
	}

	/**
	 * Determina si la firma es válida
	 * 
	 * @return Cierto si la firma es válida
	 * @throws SignatureException Error tratando el objeto firma
	 * @throws HashingException Error obteniendo el hash del documento
	 * @throws NormalizeCertificateException Alguno de los certificados no puede ser 
	 * 	normalizado al formato reconocido por el proveedor criptográfico de Arangi o su 
	 * 	firma no es correcta o no puede ser analizada
	 */
	public ValidationResult[] isValid() throws HashingException, SignatureException, NormalizeCertificateException {
		return isValid (ArangiUtil.getACCVCaList());
	}
	
	
	//-- Métodos privados
	
	private static PDFSignature sign (ACCVDeviceManager[] managers, IDocument pdfDocument, 
			String digitalSignatureAlgorithm, String reason, boolean isVisible, byte[] image, 
			float llX, float llY, float urX, float urY, int page, boolean withTimeStamp) throws AliasNotFoundException, LoadingObjectException, PDFDocumentException, 
			SignatureException, HashingException, CertificateCANotFoundException, InvalidCertificateException, AlgorithmNotSuitableException {
		
		//-- Obtener alias
		String[] alias = new String [managers.length];
		for (int i = 0; i < managers.length; i++) {
			alias[i] = managers[i].getSignatureAlias();
		}
		
		//-- Pasar los managers a objetos de arangí base
		DeviceManager[] deviceManagers = new DeviceManager[managers.length];
		for (int i = 0; i < deviceManagers.length; i++) {
			deviceManagers[i] = (DeviceManager) managers[i];
		}
		
		URL url = null;
		if (withTimeStamp) {
			url = TimeStamp.getURLACCVTSA();
		}
		
		return new PDFSignature (sign (deviceManagers, alias, pdfDocument, digitalSignatureAlgorithm, url, 
				null, null, ArangiUtil.getACCVCaList(), reason, isVisible, image, llX, llY, urX, urY, page));

	}

}
