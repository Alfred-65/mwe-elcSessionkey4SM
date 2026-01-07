/*
 * Copyright 2026 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes
 * by gematik find details in the "Readme" file.
 */

package de.gematik.smartcards.mwe.elc_sessionkey4sm;

import static de.gematik.smartcards.utils.AfiUtils.LINE_SEPARATOR;
import static de.gematik.smartcards.utils.AfiUtils.UNEXPECTED;

import de.gematik.smartcards.crypto.AesKey;
import de.gematik.smartcards.crypto.AfiElcParameterSpec;
import de.gematik.smartcards.crypto.AfiElcUtils;
import de.gematik.smartcards.crypto.EcPrivateKeyImpl;
import de.gematik.smartcards.crypto.EcPublicKeyImpl;
import de.gematik.smartcards.crypto.X509Utils;
import de.gematik.smartcards.g2icc.cvc.Cvc;
import de.gematik.smartcards.g2icc.cvc.TrustCenter;
import de.gematik.smartcards.sdcom.apdu.CommandApdu;
import de.gematik.smartcards.sdcom.apdu.ResponseApdu;
import de.gematik.smartcards.tlv.BerTlv;
import de.gematik.smartcards.tlv.ConstructedBerTlv;
import de.gematik.smartcards.utils.AfiUtils;
import de.gematik.smartcards.utils.EafiHashAlgorithm;
import de.gematik.smartcards.utils.Hex;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.jetbrains.annotations.VisibleForTesting;

/** Main class of the MWE. */
@Slf4j
public final class App {
  /** Path to "resources" folder. */
  private static final Path RESOURCES; // */

  /*
   * static
   */
  static {
    Path path = null;
    for (val i : List.of("src/main/resources", "app/src/main/resources")) {
      val tmp = Path.of(i);
      if (Files.isDirectory(tmp)) {
        path = tmp;
        break;
      } // end fi
    } // end For (i...)

    if (null == path) {
      throw new IllegalArgumentException("resource-folder not found");
    } // end fi

    RESOURCES = path.normalize().toAbsolutePath();
    log.atInfo().log("RESOURCES = {}", RESOURCES);
  } // end static */

  /**
   * Main method.
   *
   * @param args command line arguments, not used hereafter
   */
  public static void main(final String[] args) {
    log.atInfo().log("main: begin");

    try {
      CommandAPDU cmd;
      ResponseAPDU rsp;

      // --- initialization for handling CV-certificates
      TrustCenter.initializeCache(RESOURCES.resolve("pki-cvc.g2")); // cache for CVC
      val myCaCvc = getMyCaCvc();
      val myEeCvc = getMyEeCvc();
      val myPrivatekey = getPrivateKey();
      checkCvcChain(myCaCvc, myEeCvc, myPrivatekey);

      // --- initialization for card communication
      val factory = TerminalFactory.getDefault();
      val terminals = factory.terminals();
      val list = terminals.list(CardTerminals.State.CARD_PRESENT);
      log.atInfo().log("CardPresent: {}", list);
      val ifd = list.get(0);
      val icc = ifd.connect("T=1");
      val cc = icc.getBasicChannel();
      // ... we now have a logical channel "cc" usable for card communication
      // ... assertion: we have a contact based communication to the eGK

      // ###########################################################################
      // ##########           Commands from A_27008, SceOpenEgk           ##########
      // ###########################################################################
      // --- Select MF
      log.atDebug().log("SceOpenEgk, element 1: select MF");
      cmd = new CommandAPDU(Hex.toByteArray("00 a4 040c   07 D2760001448000"));
      rsp = cc.transmit(cmd);
      checkSw(rsp, 0x9000);

      // --- Read Binary: retrieve content of EF.Version2
      log.atDebug().log("SceOpenEgk, element 2: read EF.Version2");
      cmd = new CommandAPDU(Hex.toByteArray("00 b0 9100   00"));
      rsp = cc.transmit(cmd);
      checkSw(rsp, 0x9000, 0x6281);
      showEfVersion2(rsp);

      // ###########################################################################
      // ##########           Commands from A_27001, SceReadCvc           ##########
      // ###########################################################################
      // --- Read Binary: retrieve Sub-CA-CVC from eGK
      log.atDebug().log("SceReadCvc, element 1: read EF.C.CA.CS.E256");
      cmd = new CommandAPDU(Hex.toByteArray("00 b0 8700   00"));
      rsp = cc.transmit(cmd);
      checkSw(rsp, 0x9000, 0x6281);
      val egkCaCvc = new Cvc(rsp.getData());
      log.atTrace().log("Sub-CA-CVC:{}{}", LINE_SEPARATOR, egkCaCvc);
      if (!Cvc.SignatureStatus.SIGNATURE_VALID.equals(egkCaCvc.getSignatureStatus())) {
        throw new IllegalArgumentException("invalid Sub-CA-CVC");
      } // end fi

      // --- Read Binary: retrieve End-Entity-CVC from eGK
      log.atDebug().log("SceReadCvc, element 2: read EF.C.eGK.AUT_CVC.E256");
      cmd = new CommandAPDU(Hex.toByteArray("00 b0 8600   00"));
      rsp = cc.transmit(cmd);
      checkSw(rsp, 0x9000, 0x6281);
      val egkEeCvc = new Cvc(rsp.getData());
      log.atTrace().log("End-Entity-CVC:{}{}", LINE_SEPARATOR, egkEeCvc);
      if (!Cvc.SignatureStatus.SIGNATURE_VALID.equals(egkEeCvc.getSignatureStatus())) {
        throw new IllegalArgumentException("invalid End-Entity-CVC");
      } // end fi

      // --- List Public Key: retrieve key-identifier of public keys cached by eGK
      log.atDebug().log("SceReadCvc, element 3: List Public Key");
      cmd = new CommandAPDU(Hex.toByteArray("80 ca 0100   00   0000"));
      rsp = cc.transmit(cmd);
      checkSw(rsp, 0x9000, 0x6281);
      val listKeyIdentifier = extractKeyIdentifier(rsp);
      log.atTrace().log("keyIdentifier from cache: {}", listKeyIdentifier);

      // --- estimate CVC-chain to be imported into eGK
      val chain = TrustCenter.getChain(myEeCvc, egkCaCvc.getCar());
      chain.forEach(
          cvc -> log.atTrace().log("chain1, CAR, CHR: {}, {}", cvc.getCar(), cvc.getChr()));
      while (!chain.isEmpty()) {
        val lastCvc = chain.getLast();
        val lastChr = lastCvc.getChr();
        if (listKeyIdentifier.contains(lastChr)) {
          // ... key already in the cache of the ICC
          //     => no need to import it again
          chain.removeLast();
        } else {
          // ... key not yet in the cache of the ICC
          //     => do not change the chain
          break;
        } // end else
      } // end While (chain not empty)
      chain.forEach(
          cvc -> log.atTrace().log("chain2, CAR, CHR: {}, {}", cvc.getCar(), cvc.getChr()));

      // ###########################################################################
      // ##########            Commands from A_27002, SceTC1              ##########
      // ###########################################################################
      log.atDebug().log("SceTC1, element 1: MSE set PrK.eGK.AUT_CVC.E256 for elcSessionkey4SM");
      cmd = new CommandAPDU(Hex.toByteArray("00 22 41A4   06 (84-01-09) || (80-01-54)"));
      rsp = cc.transmit(cmd);
      checkSw(rsp, 0x9000);

      // element 2, import CVC-chain
      for (int i = chain.size(); i-- > 0; ) { // NOPMD assignment in operand
        log.atDebug().log("SceTC1, element 2.1: MSE Set, see (N103.300)");
        val crt = BerTlv.getInstance(0x83, chain.get(i).getCar()).getEncoded();
        cmd = new CommandAPDU(0x00, 0x22, 0x81, 0xb6, crt);
        rsp = cc.transmit(cmd);
        checkSw(rsp, 0x9000);

        log.atDebug().log("SceTC1, element 2.2: PSO Verify Certificate, see (N095.410)");
        val template = chain.get(i).getValueField();
        cmd = new CommandAPDU(0x00, 0x2a, 0x00, 0xbe, template);
        rsp = cc.transmit(cmd);
        checkSw(rsp, 0x9000);
      } // end For (i...)

      // --- General Authenticate, step 1
      log.atDebug().log("SceTC1, element 3: General Authenticate, step 1");
      val cmdDataField =
          BerTlv.getInstance(0x7c, BerTlv.getInstance(0xc3, myEeCvc.getChr()).getEncoded())
              .getEncoded();
      cmd = new CommandAPDU(0x10, 0x86, 0x00, 0x00, cmdDataField, 256);
      rsp = cc.transmit(cmd);
      checkSw(rsp, 0x9000);

      // ###########################################################################
      // ##########          Commands from A_27003, SceReadX.509          ##########
      // ###########################################################################
      // --- General Authentication, step 2
      val dp = AfiElcParameterSpec.brainpoolP256r1; // domain parameter
      val tlv7c = (ConstructedBerTlv) BerTlv.getInstance(rsp.getData());
      val tlv85 = tlv7c.getPrimitive(0x85).orElseThrow();
      val uncompressed = tlv85.getValueField();
      val opponentW = AfiElcUtils.os2p(uncompressed, dp); // create point on elliptic curve
      val ephemeralPukOpponent = new EcPublicKeyImpl(opponentW, dp); // create public key
      val ephemeralSelf = new EcPrivateKeyImpl(dp); // create ephemeral ECC key pair
      val myEphemeralPublicKey = ephemeralSelf.getPublicKey();
      val myEphemeralPoint = myEphemeralPublicKey.getW();
      val my85 = BerTlv.getInstance(0x85, AfiElcUtils.p2osUncompressed(myEphemeralPoint, dp));
      val my7c = BerTlv.getInstance(0x7c, my85.getEncoded());
      log.atDebug().log("SceReadX.509, element 1: General Authenticate, step 2");
      cmd = new CommandAPDU(0x00, 0x86, 0x00, 0x00, my7c.getEncoded());
      rsp = cc.transmit(cmd);
      checkSw(rsp, 0x9000);

      // --- calculate session key context
      val k1 = // (N085.056)c.1
          AfiElcUtils.sharedSecret(ephemeralSelf, egkEeCvc.getPublicKey());
      val k2 = AfiElcUtils.sharedSecret(myPrivatekey, ephemeralPukOpponent); // (N085.056)c.1
      val kd = AfiUtils.concatenate(k1, k2); // (N085.056)c.3
      log.atTrace().log("key derivation data, kd = '{}'", Hex.toHexDigits(kd));
      val kdEnc = AfiUtils.concatenate(kd, Hex.toByteArray("0000 0001"));
      val kdMac = AfiUtils.concatenate(kd, Hex.toByteArray("0000 0002"));
      val kEnc = new AesKey(EafiHashAlgorithm.SHA_1.digest(kdEnc), 0, 16);
      val kMac = new AesKey(EafiHashAlgorithm.SHA_1.digest(kdMac), 0, 16);
      val ssc = new byte[16]; // Send Sequence Counter

      // --- Select DF.ESIGN (with secure messaging)
      log.atDebug().log("SceReadX.509, element 2: Select DF.ESIGN");
      cmd = selectDfEsign(kEnc, kMac, ssc);
      rsp = cc.transmit(cmd);
      rsp = unprotectIsoCase3(rsp, kMac, ssc);
      checkSw(rsp, 0x9000);

      // --- Read Binary, read EF.C.CH.AUT.E256 (with secure messaging)
      log.atDebug().log("SceReadX.509, element 3: read EF.C.CH.AUT.E256");
      cmd = readX509(kMac, ssc);
      rsp = cc.transmit(cmd);
      rsp = unprotectIsoCase4(rsp, kMac, ssc);
      checkSw(rsp, 0x9000, 0x6281);
      val rawX509 = rsp.getData();
      val x509 = X509Utils.generateCertificate(rawX509);
      log.atInfo().log("X.509 AUT.E256:{}{}", LINE_SEPARATOR, x509);

      // --- disconnect from card
      icc.disconnect(true);
    } catch (Exception e) {
      log.atError().log(UNEXPECTED, e);
    } // end Catch (...)
    log.atInfo().log("main: end");
  } // end method */

  /**
   * Retrieve on-side Sub-CA-CVC.
   *
   * @return on-side Sub-CA-CVC
   * @throws IOException if an I/O error occurs
   */
  private static Cvc getMyCaCvc() throws IOException {
    val path = RESOURCES.resolve("certificates/cvc/DEGXX120223.cer");
    val raw = Files.readAllBytes(path);

    return new Cvc(raw);
  } // end method */

  /**
   * Retrieve on-side Sub-CA-CVC.
   *
   * @return on-side Sub-CA-CVC
   * @throws IOException if an I/O error occurs
   */
  private static Cvc getMyEeCvc() throws IOException {
    val path = RESOURCES.resolve("certificates/cvc/80276001011699902101-cvc-flag0.crt");
    val raw = Files.readAllBytes(path);

    return new Cvc(raw);
  } // end method */

  /**
   * Retrieves private key of CVC-identity.
   *
   * @return private key of CVC-identity
   * @throws Exception if something went wrong
   */
  @VisibleForTesting
  /* package */ static ECPrivateKey getPrivateKey() throws Exception {
    val pathPassword = RESOURCES.resolve("certificates/cvc/password.txt");
    val password = Files.readString(pathPassword).trim().toCharArray();

    val pathP12 = RESOURCES.resolve("certificates/cvc/80276001011699902101-cvc-flag0.p12");
    try (val is = new FileInputStream(pathP12.toFile())) {
      val keyStore = KeyStore.getInstance("PKCS12");
      keyStore.load(is, password);

      val aliases = keyStore.aliases().asIterator();
      val alias = aliases.next();
      val prk = keyStore.getKey(alias, password);

      return (ECPrivateKey) prk;
    } // end try-with-resources
  } // end method */

  /**
   * Extracts key identifiers from a List Public Key response APDU.
   *
   * @param rsp response APDU of a List Public Key command
   * @return list of key identifier
   */
  private static List<String> extractKeyIdentifier(final ResponseAPDU rsp) {
    final List<String> result = new ArrayList<>();

    final List<BerTlv> template =
        ((ConstructedBerTlv) BerTlv.getInstance(0x20, rsp.getData())).getTemplate();

    template.stream()
        .filter(tlv -> 0xe0 == tlv.getTag())
        .map(tlv -> ((ConstructedBerTlv) tlv).getTemplate())
        .filter(temp -> temp.size() >= 2)
        .forEach(
            temp -> {
              val aid = Hex.toHexDigits(temp.getFirst().getValueField());
              val keyDo = temp.get(1);
              if (keyDo instanceof ConstructedBerTlv kt) {
                val keyRef = Hex.toHexDigits(kt.getTemplate().getFirst().getValueField());

                if ("d2760001448000".equals(aid)) { // NOPMD literal in if statement
                  result.add(keyRef);
                } // end fi
              } // end fi
            }); // end forEach(tlv -> ...)

    return Collections.unmodifiableList(result);
  } // end method */

  /**
   * Checks given CVC-information.
   *
   * @param ca Sub-CA-CVC
   * @param ee End-Entity-CVC
   * @param privateKey private key
   * @throws IllegalArgumentException if something is wrong
   */
  private static void checkCvcChain(final Cvc ca, final Cvc ee, final ECPrivateKey privateKey) {
    if (!Cvc.SignatureStatus.SIGNATURE_VALID.equals(ca.getSignatureStatus())) {
      throw new IllegalArgumentException("invalid Sub-CA-CVC");
    } // end fi

    if (!Cvc.SignatureStatus.SIGNATURE_VALID.equals(ca.getSignatureStatus())) {
      throw new IllegalArgumentException("invalid End-Entity-CVC");
    } // end fi

    val caChr = ca.getChr();
    val eeCar = ee.getCar();

    if (!caChr.equals(eeCar)) {
      throw new IllegalArgumentException("not a CVC-chain");
    } // end fi

    val prk = new EcPrivateKeyImpl(privateKey);
    if (!prk.getPublicKey().equals(ee.getPublicKey())) {
      throw new IllegalArgumentException("public key mismatch");
    } // end fi
  } // end method */

  /**
   * Logs human-readable form of content from EF.Version2.
   *
   * @param rsp response APDU from reading EF.Version2
   */
  private static void showEfVersion2(final ResponseAPDU rsp) {
    val tlv = (ConstructedBerTlv) BerTlv.getInstance(rsp.getData());

    log.atTrace().log("content EF.Version2:{}{}", LINE_SEPARATOR, tlv.toStringTree());
  } // end method */

  /**
   * Prepare Select DF.ESIGN command with secure messaging.
   *
   * @param kEnc encipher key
   * @param kMac CMAC key
   * @param ssc send sequence counter
   * @return Select DF.ESIGN command APDU secured with secure messaging
   */
  private static CommandAPDU selectDfEsign(final AesKey kEnc, final AesKey kMac, final byte[] ssc) {
    AfiUtils.incrementCounter(ssc); // increment send sequence counter
    val plain = Hex.toByteArray("a000000167455349474e");
    val ivEnc = kEnc.encipherCbc(ssc);
    val cipher = Hex.toHexDigits(kEnc.encipherCbc(kEnc.padIso(plain), ivEnc));
    val protectedDo = BerTlv.getInstance(0x87, "01" + cipher).getEncoded();
    val header = Hex.toByteArray("0c a4 040c");
    val macInput = AfiUtils.concatenate(ssc, kMac.padIso(header), kMac.padIso(protectedDo));
    val mac = kMac.calculateCmac(macInput, 8); // see (N002.810)h
    val macDo = BerTlv.getInstance(0x8e, mac).getEncoded();
    val cmdData = AfiUtils.concatenate(protectedDo, macDo);
    val result = new CommandAPDU(0x0c, 0xa4, 0x04, 0x0c, cmdData, 256);

    log.atTrace().log("Select DF.ESIGN: {}", new CommandApdu(result.getBytes()));

    return result;
  } // end method */

  /**
   * Prepare Read Binary command with secure messaging.
   *
   * @param kMac CMAC key
   * @param ssc send sequence counter
   * @return Read Binary command APDU secured with secure messaging
   */
  private static CommandAPDU readX509(final AesKey kMac, final byte[] ssc) {
    AfiUtils.incrementCounter(ssc); // increment send sequence counter
    val header = Hex.toByteArray("0c b0 8400");
    val leDo = BerTlv.getInstance(0x97, "0000").getEncoded();
    val macInput = AfiUtils.concatenate(ssc, kMac.padIso(header), kMac.padIso(leDo));
    val mac = kMac.calculateCmac(macInput, 8); // see (N002.810)h
    val macDo = BerTlv.getInstance(0x8e, mac).getEncoded();
    val cmdData = AfiUtils.concatenate(leDo, macDo);
    val result = new CommandAPDU(0x0c, 0xb0, 0x84, 0x00, cmdData, 0x1_0000);

    log.atTrace().log("Read X.509: {}", new CommandApdu(result.getBytes()));

    return result;
  } // end method */

  /**
   * Unprotect a response APDU for an ISO-case 3 command.
   *
   * @param kMac CMAC key
   * @param ssc send sequence counter
   * @return unprotected response APDU
   * @throws IllegalArgumentException if anything is wrong
   */
  private static ResponseAPDU unprotectIsoCase3(
      final ResponseAPDU rsp, final AesKey kMac, final byte[] ssc) {
    log.atTrace().log("protected  : {}", new ResponseApdu(rsp.getBytes()));
    AfiUtils.incrementCounter(ssc); // increment send sequence counter
    val ctlv = (ConstructedBerTlv) BerTlv.getInstance(0x20, rsp.getData());
    val swDo = ctlv.getPrimitive(0x99).orElseThrow();
    val preMac = ctlv.getPrimitive(0x8e).orElseThrow().getValueField();
    val macInput = AfiUtils.concatenate(ssc, kMac.padIso(swDo.getEncoded()));
    val expMac = kMac.calculateCmac(macInput, 8);
    if (!Arrays.equals(expMac, preMac)) {
      throw new IllegalArgumentException("wrong MAC");
    } // end fi
    // ... MAC is correct
    val result = new ResponseAPDU(swDo.getValueField());

    log.atTrace().log("unprotected: {}", new ResponseApdu(result.getBytes()));

    return result;
  } // end method */

  /**
   * Unprotect a response APDU for an ISO-case 3 command.
   *
   * @param kMac CMAC key
   * @param ssc send sequence counter
   * @return unprotected response APDU
   * @throws IllegalArgumentException if anything is wrong
   */
  private static ResponseAPDU unprotectIsoCase4(
      final ResponseAPDU rsp, final AesKey kMac, final byte[] ssc) {
    log.atTrace().log("protected  : {}", new ResponseApdu(rsp.getBytes()));
    AfiUtils.incrementCounter(ssc); // increment send sequence counter
    val ctlv = (ConstructedBerTlv) BerTlv.getInstance(0x20, rsp.getData());
    val plainDo = ctlv.getPrimitive(0x81).orElseThrow();
    val swDo = ctlv.getPrimitive(0x99).orElseThrow();
    val preMac = ctlv.getPrimitive(0x8e).orElseThrow().getValueField();
    val message = AfiUtils.concatenate(plainDo.getEncoded(), swDo.getEncoded());
    val macInput = AfiUtils.concatenate(ssc, kMac.padIso(message));
    val expMac = kMac.calculateCmac(macInput, 8);
    if (!Arrays.equals(expMac, preMac)) {
      throw new IllegalArgumentException("wrong MAC");
    } // end fi
    // ... MAC is correct
    val result =
        new ResponseAPDU(AfiUtils.concatenate(plainDo.getValueField(), swDo.getValueField()));

    log.atTrace().log("unprotected: {}", new ResponseApdu(result.getBytes()));

    return result;
  } // end method */

  /**
   * Check for unwanted status codes.
   *
   * @param rsp response APDU
   * @param expected list of expected status words
   * @throws IllegalArgumentException if an unexpected status word occurs
   */
  private static void checkSw(final ResponseAPDU rsp, final int... expected) {
    val collection = Arrays.stream(expected).boxed().collect(Collectors.toSet());

    if (!collection.contains(rsp.getSW())) {
      throw new IllegalArgumentException(String.format("unexpected SW='%04x'", rsp.getSW()));
    } // end fi
  } // end method */
} // end class
