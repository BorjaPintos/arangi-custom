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
import java.io.IOException;
import java.io.InputStream;

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
import es.accv.arangi.base.exception.signature.RetrieveOCSPException;
import es.accv.arangi.base.exception.signature.SignatureException;
import es.accv.arangi.base.exception.signature.SignatureNotFoundException;
import es.accv.arangi.base.exception.timestamp.ResponseTimeStampException;
import es.accv.arangi.base.signature.PDFSignature;
import es.accv.arangi.base.util.validation.ValidationResult;
import es.accv.arangi.device.ACCVDeviceManager;
import es.accv.arangi.timestamp.TimeStamp;
import es.accv.arangi.util.ArangiUtil;

/**
 * Clase para manejar firmas en PDF (PAdES-A) seg�n los est�ndares 
 * <a href="http://www.etsi.org/deliver/etsi_ts/102700_102799/10277804/01.01.01_60/ts_10277804v010101p.pdf" target="estandar">ETSI TS 102 778-4 V1.2.1</a> 
 * y <a href="http://www.telecomforum.eu/deliver/etsi_ts/119100_119199/11914402/01.01.01_60/ts_11914402v010101p.pdf" target="estandar">ETSI TS 119 144-2 V1.1.1</a>,
 * basado en la norma <a href="http://www.iso.org/iso/catalogue_detail.htm?csnumber=51502" target="estandar">ISO 32000-1</a><br><br>
 * 
 * Por motivos de compatibilidad la clase sigue llam�ndose PAdESLTVSignature 
 * aunque ser�a m�s correcto llamarla PAdESASignature, ya que siempre se
 * trabajar� con sellos de tiempo de documento, que son lo que diferencia
 * a un PAdES-LTV de un PAdES-A seg�n la norma ETSI TS 119 144-2.<br><br>
 * 
 * La norma ETSI TS 119 144-2 exige a�adir m�s informaci�n de validaci�n que
 * la que se establec�a en la ETSI TS 102 778-4. Por ello, las firmas realizadas 
 * con versiones de Arang� anteriores a la 1.1.4 no ser�n consideradas v�lidas por 
 * dicha versi�n o versiones posteriores. Para evitar este incoveniente a aquellos 
 * desarrollos que se hayan realizado con versiones antiguas es posible activar un 
 * flag est�tico antes de la validaci�n que permitir� que en las validaciones no 
 * se tenga en cuenta la informaci�n extra exigida por la nueva norma:<br><br>
 * 
 * <code>
 * olderVersionsAllowed = true;
 * </code><br><br>
 * 
 * Este tipo de firmas cumplen con los requisitos para ser firmas longevas. En 
 * ellas se incluye toda la informaci�n necesaria para validar los certificados
 * de las firmas. Tambi�n se a�ade un sello de tiempos para el documento que
 * da garantias sobre la fecha en la que se realizaron las firmas.<br><br>
 * 
 * Las �ltimas versiones de Adobe Acrobat ya utilizan este tipo de firmas, aunque 
 * existen algunas diferencias entre las firmas PAdES-LTV obtenidas por Adobe y las
 * normas de la ETSI. En la documentaci�n de Arang� debe haber una explicaci�n de
 * cuales son estas diferencias.<br><br>
 * 
 * Para evitar problemas de saturaci�n de memoria con ficheros PDF muy grandes,
 * esta clase siempre trabajar� sobre un objeto java.io.File. Si el objeto no se 
 * inicializa con un fichero se crear� un archivo temporal en la carpeta temporal 
 * de Arangi: {@link #getArangiTemporalFolder() getArangiTemporalFolder}.<br><br>
 * 
 * Existen dos m�todos para obtener una firma PAdES-LTV, dependiendo de si se desea 
 * una firma visible o invisible. En el caso de las firmas visibles hay que proporcionar 
 * al m�todo las coordenadas de las esquinas inferior izquierda y superior derecha, as� 
 * como el n�mero de p�gina donde se desea ubicar la firma. Tambi�n es posible asociar
 * una imagen a la firma.<br><br>
 * 
 * <code>
 * KeyStoreManager manager = new KeyStoreManager (...,...);<br>
 * ByteArrayDocument documentPDF = new ByteArrayDocument (...);<br><br>
 * 
 * //-- Firma invisible<br>
 * PAdESLTVSignature signatureInv = PAdESLTVSignature.sign (new ACCVDeviceManager[] {manager},documentPDF, "Porque quiero firmarlo");<br><br>
 * 
 * //-- Firma visible<br>
 * PAdESLTVSignature signatureVis = PAdESLTVSignature.sign (new ACCVDeviceManager[] {manager},documentPDF, "Porque quiero firmarlo",
 *      true, Util.readStream(ClassLoader.getSystemResourceAsStream("signature/chip.gif")), 100, 100, 300, 200, 1);<br><br>
 * </code>
 * 
 * En la p�gina 1 de la segunda firma, en la ubicaci�n indicada por las coordenadas, se 
 * ver� la imagen chip.gif como una firma realizada sobre el PDF.<br><br>
 * 
 * El primer par�metro de la firma es un array de managers, ya que es posible realizar 
 * varias firmas a la vez. Es importante destacar que una vez se han a�adido los campos 
 * que hacen de un PDF firmado un PAdES-LTV ya no es posible volver a firmar el documento. 
 * Si un documento se va firmar por varias personas de forma no simultanea lo que se debe 
 * hacer es realizar las firmas en un PDF con firma simple y, tras la �ltima firma 
 * completar a PAdES-LTV. Por supuesto, entre el principio y el fin del proceso ninguno 
 * de los certificados implicados podr� caducar o ser revocado.<br><br>
 * 
 * <code>
 * //-- Primera firma<br>
 * KeyStoreManager manager1 = new KeyStoreManager (...,...);<br>
 * ByteArrayDocument documentPDF = new ByteArrayDocument (...);<br>
 * PDFSignature signature = PDFSignature.sign (new ACCVDeviceManager[] {manager1},documentPDF, "Firma 1");<br><br>
 * 
 * //-- Segunda firma (d�as m�s tarde)<br>
 * KeyStoreManager manager2 = new KeyStoreManager (...,...);<br>
 * documentPDF = new ByteArrayDocument (signature.toByteArray());<br>
 * signature = PDFSignature.sign (new ACCVDeviceManager[] {manager2},documentPDF, "Firma 2");<br><br>
 * 
 * //-- Completar la firma para que sea PAdES-LTV<br>
 * PAdESLTVSignature padesLTV = PAdESLTVSignature.completeToPAdESLTV(signature);<br><br>
 * </code><br><br>
 * 
 * La validez de una firma longeva se halla limitada a la vida del certificado del �ltimo sello 
 * de tiempos de documento que contiene el PDF, aunque erroneamente se suele pensar que una firma 
 * longeva puede validarse eternamente. Por ejemplo, el certificado de la TSA de la ACCV caducar� 
 * el 18 de Noviembre de 2016, lo que implica que a partir de esa fecha las firmas PAdES-LTV 
 * realizadas con la TSA de la ACCV dejar�n de ser v�lidas. Con el objeto de alargar la vida de
 * una firma longeva ser� necesario realizar un resellado de la misma cuando se cambie el certificado
 * de la TSA. Este ser�a el c�digo para realizar un resellado: <br><br>
 * 
 * <code>
 * ByteArrayDocument document = new ByteArrayDocument (...);<br>
 * PAdESLTVSignature signature = new PAdESLTVSignature(document);<br>
 * signature.addDocumentTimeStamp();<br>
 * signature.save(...);<br>
 * </code>
 *  
 * @author <a href="mailto:jgutierrez@accv.es">Jos� M Guti�rrez</a>
 */
public class PAdESLTVSignature extends es.accv.arangi.base.signature.PAdESLTVSignature {

	/**
	 * Inicializa el objeto con el contenido de un fichero PDF firmado.
	 * 
	 * @param pdfContentBytes Array de bytes con el contenido del fichero PDF firmado
	 * @throws PDFDocumentException El fichero no es un PDF correcto o bien no puede 
	 * 	ser le�do
	 * @throws SignatureNotFoundException El fichero es un PDF pero no est� firmado
	 * @throws IOException No se puede crear el fichero temporal
	 */
	public PAdESLTVSignature(byte[] pdfContentBytes) throws PDFDocumentException,
			SignatureNotFoundException, IOException {
		super(pdfContentBytes);
	}

	/**
	 * Inicializa el objeto con un fichero PDF firmado.
	 * 
	 * @param pdfFile Fichero PDF firmado
	 * @throws PDFDocumentException El fichero no es un PDF correcto o bien no puede 
	 * 	ser le�do
	 * @throws SignatureNotFoundException El fichero es un PDF pero no est� firmado
	 */
	public PAdESLTVSignature(File pdfFile) throws PDFDocumentException,
			SignatureNotFoundException {
		super(pdfFile);
	}

	/**
	 * Inicializa el objeto con un documento que debe contener un fichero PDF firmado.
	 * 
	 * @param document Documento con el contenido del fichero PDF firmado
	 * @throws PDFDocumentException El fichero no es un PDF correcto o bien no puede 
	 * 	ser le�do
	 * @throws SignatureNotFoundException El fichero es un PDF pero no est� firmado
	 * @throws IOException No se puede crear el fichero temporal
	 */
	public PAdESLTVSignature(IDocument document) throws PDFDocumentException,
			SignatureNotFoundException, IOException {
		super(document);
	}

	/**
	 * Inicializa el objeto con un stream de lectura al contenido de un fichero PDF firmado.
	 * 
	 * @param streamPDF Stream de lectura al contenido del fichero PDF firmado
	 * @throws PDFDocumentException El fichero no es un PDF correcto o bien no puede 
	 * 	ser le�do
	 * @throws SignatureNotFoundException El fichero es un PDF pero no est� firmado
	 * @throws IOException No se puede crear el fichero temporal
	 */
	public PAdESLTVSignature(InputStream streamPDF) throws PDFDocumentException,
			SignatureNotFoundException, IOException {
		super(streamPDF);
	}

	/*
	 * S�lo para pasar de una firma base a una de arangi
	 */
	private PAdESLTVSignature(es.accv.arangi.base.signature.PAdESLTVSignature signature) {
		super(signature);
	}

	/**
	 * Obtiene un objeto {@link PAdESLTVSignature PDFSignature} tras firmar un documento PDF.
	 * La firma es invisible.
	 * 
	 * @param managers Dispositivos criptogr�fico que realizar�n la firma
	 * @param pdfDocument Documento PDF a firmar
	 * @param reason Texto que aparecer� junto a la firma como raz�n. Si se pasa un valor
	 * 	nulo se escribir� un texto por defecto.
	 * @return Documento PDF firmado, con sello de tiempos y respuesta OCSP
	 * @throws AliasNotFoundException El alias donde se encuentra la clave privada usada para
	 * 	realizar la firma no existe
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws PDFDocumentException El documento no es un fichero PDF o es un PDF mal formado
	 * @throws SignatureException No se puede realizar la firma
	 * @throws RetrieveOCSPException No es posible obtener una respuesta OCSP para
	 * 	asociarla a la firma
	 * @throws HashingException Excepci�n obteniendo el hash que ser� sellado por la TSA
	 * @throws CertificateCANotFoundException La lista de certificado de CA no contiene el 
	 * 	emisor del certificado de firma o existe pero tiene un formato no normalizable por 
	 * 	el proveedor criptogr�fico de Arangi
	 * @throws InvalidCertificateException El certificado con el que se firma est� revocado
	 * @throws NormalizeCertificateException Alguno de los certificados de firma o de sus cadenas
	 * 	de certificaci�n no puede ser normalizado
	 */
	public static PAdESLTVSignature sign (ACCVDeviceManager managers[], IDocument pdfDocument, String reason) throws AliasNotFoundException, 
		LoadingObjectException, PDFDocumentException, SignatureException, RetrieveOCSPException, HashingException, CertificateCANotFoundException, 
		InvalidCertificateException, NormalizeCertificateException {
		
		try {
			return sign (managers, pdfDocument, null, reason, false, null, -1, -1, -1, -1, 0);
		} catch (AlgorithmNotSuitableException e) {
			throw new SignatureException("El algoritmo por defecto no deber�a provocar este error", e);
		}
	}
	
	/**
	 * Obtiene un objeto {@link PAdESLTVSignature PDFSignature} tras firmar un documento PDF.<br><br>
	 * 
	 * Si la firma es visible se le puede asociar una imagen. El punto 0,0 de la p�gina 
	 * se encuentra en la esquina inferior izquierda de la misma. Un p�gina tiene 
	 * aproximadamente unas dimensiones de 580x850. 
	 * 
	 * @param managers Dispositivos criptogr�fico que realizar�n la firma
	 * @param pdfDocument Documento PDF a firmar
	 * @param digitalSignatureAlgorithm Algoritmo de firma (si nulo algoritmo por defecto)
	 * @param reason Texto que aparecer� junto a la firma como raz�n. Si se pasa un valor
	 * 	nulo se escribir� un texto por defecto.
	 * @param isVisible Si tiene un valor cierto se crear� una firma visible.
	 * @param image Imagen de la firma. Puede tener un valor nulo.
	 * @param llX Posici�n X de la esquina inferior izquierda de la firma en la p�gina (caso de ser visible)
	 * @param llY Posici�n Y de la esquina inferior izquierda de la firma en la p�gina (caso de ser visible) 
	 * @param urX Posici�n X de la esquina superior derecha de la firma en la p�gina (caso de ser visible)
	 * @param urY Posici�n Y de la esquina superior derecha de la firma en la p�gina (caso de ser visible)
	 * @param page P�gina en la que se situar� la firma si �sta es visible (1 es la primera p�gina)
	 * @return Documento PDF firmado, con sello de tiempos y respuesta OCSP
	 * @throws AliasNotFoundException El alias donde se encuentra la clave privada usada para
	 * 	realizar la firma no existe
	 * @throws LoadingObjectException No ha sido posible cargar la clave privada usada para
	 * 	realizar la firma
	 * @throws PDFDocumentException El documento no es un fichero PDF o es un PDF mal formado
	 * @throws SignatureException No se puede realizar la firma
	 * @throws RetrieveOCSPException No es posible obtener una respuesta OCSP para
	 * 	asociarla a la firma
	 * @throws HashingException Excepci�n obteniendo el hash que ser� sellado por la TSA
	 * @throws CertificateCANotFoundException La lista de certificado de CA no contiene el 
	 * 	emisor del certificado de firma o existe pero tiene un formato no normalizable por 
	 * 	el proveedor criptogr�fico de Arangi
	 * @throws InvalidCertificateException El certificado con el que se firma est� revocado
	 * @throws NormalizeCertificateException Alguno de los certificados de firma o de sus cadenas
	 * 	de certificaci�n no puede ser normalizado
	 * @throws AlgorithmNotSuitableException El algoritmo de firma pasado no sirve para realizar la firma
	 */
	public static PAdESLTVSignature sign (ACCVDeviceManager[] managers, IDocument pdfDocument, 
			String digitalSignatureAlgorithm, String reason, boolean isVisible, byte[] image, 
			float llX, float llY, float urX, float urY, int page) throws AliasNotFoundException, LoadingObjectException, PDFDocumentException, 
			SignatureException, RetrieveOCSPException, HashingException, CertificateCANotFoundException, InvalidCertificateException, NormalizeCertificateException, AlgorithmNotSuitableException {
		
		//-- Obtener alias
		String[] alias = new String [managers.length];
		for (int i = 0; i < managers.length; i++) {
			alias[i] = managers[i].getSignatureAlias();
		}
		
		//-- Pasar los managers a objetos de arang� base
		DeviceManager[] deviceManagers = new DeviceManager[managers.length];
		for (int i = 0; i < deviceManagers.length; i++) {
			deviceManagers[i] = (DeviceManager) managers[i];
		}
		
		return new PAdESLTVSignature (sign (deviceManagers, alias, pdfDocument, digitalSignatureAlgorithm,
				TimeStamp.getURLACCVTSA(), null, null, ArangiUtil.getACCVCaList(), reason, isVisible, image, 
				llX, llY, urX, urY, page));

	}
	
	/**
	 * M�todo que completa un fichero PDF firmado a PAdES-LTV. La firma del PDF firmado ha de ser
	 * correcta y los certificados han de ser v�lidos en este momento.
	 * 
	 * @param signature PDF firmado
	 * @return PAdES-LTV
	 * @throws PDFDocumentException El documento no es un fichero PDF o es un PDF mal formado
	 * @throws SignatureException Error completando la firma
	 * @throws RetrieveOCSPException No es posible obtener una respuesta OCSP para
	 * 	asociarla a la firma
	 * @throws HashingException Excepci�n obteniendo el hash que ser� sellado por la TSA
	 * @throws CertificateCANotFoundException La lista de certificado de CA no contiene el 
	 * 	emisor del certificado de firma o existe pero tiene un formato no normalizable por 
	 * 	el proveedor criptogr�fico de Arangi
	 * @throws InvalidCertificateException El certificado con el que se firma est� revocado
	 * @throws NormalizeCertificateException Alguno de los certificados de firma o de sus cadenas
	 * 	de certificaci�n no puede ser normalizado
	 */
	public static PAdESLTVSignature completeToPAdESLTV (PDFSignature signature) throws SignatureException, 
		RetrieveOCSPException, InvalidCertificateException, NormalizeCertificateException, PDFDocumentException, CertificateCANotFoundException, 
		HashingException {
		
		return new PAdESLTVSignature(completeToPAdESLTV(signature, TimeStamp.getURLACCVTSA(), ArangiUtil.getACCVCaList()));
		
	}
	
	/**
	 * A�ade un sello de tiempos al documento PDF (document time-stamp).
	 * 
	 * @throws SignatureException Error leyendo o guardando objetos de la firma
	 * @throws RetrieveOCSPException No es posible obtener una respuesta OCSP para el 
	 * 	certificado del �ltimo sello de tiempos del documento
	 * @throws ResponseTimeStampException No es posible obtener una respuesta del servidor
	 * 	de sello de tiempos
	 * @throws CertificateCANotFoundException El certificado del �ltimo sello de tiempos del 
	 * 	documento no pertenece a ninguna de las Autoridades de Certificaci�n de confianza
	 */
	public void addDocumentTimeStamp () throws SignatureException, RetrieveOCSPException, ResponseTimeStampException, CertificateCANotFoundException {
		addDocumentTimeStamp(TimeStamp.getURLACCVTSA(), ArangiUtil.getACCVCaList());
	}
	
	/**
	 * Determina si la firma es v�lida
	 * 
	 * @return Cierto si la firma es v�lida
	 * @throws SignatureException Error tratando el objeto firma
	 * @throws HashingException Error obteniendo el hash del documento
	 * @throws NormalizeCertificateException Alguno de los certificados no puede ser 
	 * 	normalizado al formato reconocido por el proveedor criptogr�fico de Arangi o su 
	 * 	firma no es correcta o no puede ser analizada
	 */
	public ValidationResult[] isValid() throws HashingException, SignatureException, NormalizeCertificateException {
		return isValid (ArangiUtil.getACCVCaList());
	}
	
}
