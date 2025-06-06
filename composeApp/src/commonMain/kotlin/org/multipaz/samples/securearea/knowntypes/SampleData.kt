package org.multipaz.samples.securearea.knowntypes

import kotlinx.datetime.LocalDate
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.cbor.addCborMap
import org.multipaz.cbor.buildCborArray
import org.multipaz.cbor.toDataItem
import org.multipaz.cbor.toDataItemFullDate
import org.multipaz.documenttype.DocumentAttributeType
import org.multipaz.documenttype.DocumentType
import org.multipaz.documenttype.Icon
import org.multipaz.documenttype.IntegerOption
import org.multipaz.documenttype.StringOption
import org.multipaz.util.fromBase64Url

object SampleData {

    const val GIVEN_NAME = "Erika"
    const val FAMILY_NAME = "Mustermann"
    const val GIVEN_NAME_BIRTH = "Erika"
    const val FAMILY_NAME_BIRTH = "Mustermann"
    const val GIVEN_NAMES_NATIONAL_CHARACTER = "Ерика"
    const val FAMILY_NAME_NATIONAL_CHARACTER = "Бабіак"

    const val BIRTH_DATE = "1971-09-01"
    const val BIRTH_COUNTRY = "ZZ"  // Note: ZZ is a user-assigned country-code as per ISO 3166-1
    const val ISSUE_DATE = "2024-03-15"
    const val EXPIRY_DATE = "2028-09-01"
    const val ISSUING_COUNTRY = "US"
    const val ISSUING_AUTHORITY_MDL = "Utopia Department of Motor Vehicles"
    const val ISSUING_AUTHORITY_EU_PID = "Utopia Central Registry"
    const val ISSUING_AUTHORITY_PHOTO_ID = "Utopia Central Registry"
    const val DOCUMENT_NUMBER = "987654321"
    const val PERSON_ID = "24601"

    const val UN_DISTINGUISHING_SIGN = "UTO"
    const val ADMINISTRATIVE_NUMBER = "123456789"
    const val SEX_ISO218 = 2
    const val HEIGHT_CM = 175
    const val WEIGHT_KG = 68
    const val BIRTH_PLACE = "Sample City"
    const val BIRTH_STATE = "Sample State"
    const val BIRTH_CITY = "Sample City"
    const val RESIDENT_ADDRESS = "Sample Street 123, 12345 Sample City, Sample State, Utopia"
    const val PORTRAIT_CAPTURE_DATE = "2020-03-14"
    const val PORTRAIT_BASE64URL = "_9j_4QDKRXhpZgAATU0AKgAAAAgABgESAAMAAAABAAEAAAEaAAUAAAABAAAAVgEbAAUAAAABAAAAXgEoAAMAAAABAAIAAAITAAMAAAABAAEAAIdpAAQAAAABAAAAZgAAAAAAAABIAAAAAQAAAEgAAAABAAeQAAAHAAAABDAyMjGRAQAHAAAABAECAwCgAAAHAAAABDAxMDCgAQADAAAAAQABAACgAgAEAAAAAQAAAHigAwAEAAAAAQAAAJmkBgADAAAAAQAAAAAAAAAAAAD_2wCEAAQEBAQEBAcEBAcJBwcHCQ0JCQkJDRANDQ0NDRATEBAQEBAQExMTExMTExMXFxcXFxcbGxsbGx8fHx8fHx8fHx8BBQUFCAcIDQcHDSAWEhYgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIP_dAAQACP_AABEIAJkAeAMBIgACEQEDEQH_xAGiAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgsQAAIBAwMCBAMFBQQEAAABfQECAwAEEQUSITFBBhNRYQcicRQygZGhCCNCscEVUtHwJDNicoIJChYXGBkaJSYnKCkqNDU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6g4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2drh4uPk5ebn6Onq8fLz9PX29_j5-gEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoLEQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4-Tl5ufo6ery8_T19vf4-fr_2gAMAwEAAhEDEQA_APouZf3r8_xGosgjFSSf6x_940yus84YvI5pjccA0uQoyccVyvizxHD4c06S6lbDgcZ65_pWVWsqcbs2oUJVXyoq-KvGWl-F7dmuZA854SNT8xP-FfLviHxr4i1-RmA-zwj7qr6erHtTtQke53eIvELEBz-5RurZ7BfX-VZIt7u7YS3ceO8FonQD-_Ie_wCNef8AE-ef_APXVP2ceSGhj-ZuHmXT5z35yf606a_tY0KqspDDHzHt-NT6kbfTFJcb7jbuYfwoPf6-lcsgnmzNIM56sewreCvqYyfL7pZsZYYZCvVWOVB-Xg9efpXZ2aOIxJZPGSOOx_CvO2mUEbQCvQEVrLqF5YquNpiYDaWUEfn1qpwbFTmket6TqswcQaxGCn99RwB7iutm01Y0-26cwkUAfdHb-leNadr8_mKkkMQJ-6A2Ff2BYkKfxx24r03QLjePtmnsy4-V4XG0qe4I7VxzTidcHzaHeaH4jMSo34Nn-Veo280NzGs0DB1YcV5CunQakDcWy7Jf41HANdB4evZdLnNhe8wyn5G_ut7_AF6Vthq_I7PY5cZheePNHdHoWc0cU9SSMHtS_N6GvWPDsf_Q-jJHXzG9Mmq7MynIHWppTtkb6mrVnb7ybqXG1BkGuidRQV2cVOk5tRRRuXi0yzN9e43f8s0x-VfPfiGN9e1OW91XP2Kx-eTP3S_VU_DvXruu3M1_N5yDdhhHEn95zwPwrjPEOly3UsHh22AMMPz3Ln-N-prwJ1nOXMz6mhhFSgoI8Mkik1q7bXL9f3KfLbQnsvbA9-K3ItPa2tG1Kdd0khxEn99z93P-yPyr0I-Ho2uFVgPLT73-FUNasGvdtnGuA4KAf3U9fYtQ6vQ1WGPCYdGudc1AxwZlRn-aTH3vVz7cfKPTHrWZ4jSKGcaVYDMUXEjjHzv3_AdK9_vtPXw_oxsbMbLm6XAYdUXvj07Y_CvPoPDQWBpxHlHOAPZa6Y4lJ-hyPBtqyPKbHT_tNvIzKRj5gO-Bx_hXRaVpr-QtndLvilzsPfftyMfUDGPpXpun-GY7eKMLwGZP--S3P6U5NEeOwSQjmORT-TYz-VOeKvsEMC42PJxpxtJDbuN2BwMfK69vx9a7jw6JbG4jmi5hYbQSeV_2T6r_ACrq9Q0UuiPt7bsY_A_596NO0zY23n1_Csp1-ZFxwvKzubZvLH2yIZK8SIPT_Gt94oL6ITJgk9D2PtWNY4h2MTwPlYDuOx_LirMYl0y98oHEMvK56D2_Cs4vqVKPQ7TS7gyWyxyE7k-XFamV9f0rlomlSTzk4PQ46FaufbH9B-Zr1KOKSikzxa-AbneB_9H6OKbrggDuavXzkW62cXC4yxpsCt5jtx1xn_Cq123lQlz2P61x46rf3UdeWUftmbpdms2pSTcf6MuF9Azf_Wp1ppCGB7zqZXKpn2POPStnw_b-XpzuRlpXY_ieBW7FHDFE-4_u7aMRL7kck1wxjoes6lmeWX2nrbhl6etYlvp6fPqFx9xQP_rCu4vkfUboW8C_e_z-lY3iFYY_9FXCW1uN0re4HA_pWL01O-OyieZ6pFJdziR_vSnaq-iitLUNJgsLNLZQPlXH1LVa8MW76_r5nK4htl3D6Cujntl1HxAqsD5MH7xz268ChLQu1pcvZGLJoqRywWyckNGnPrwKSXQoxpMg248sOPwQjFb-r3kFrfwLnnzBIcdhnI_StScIfDNzNzlmc_gzD_CtF1Ri9FFnAw2EdxpsD4yVO1vxH_6qoiw8qUbR0AOP51paTc4iktycLvAGfdcf0FaDfvhDJjBw0Z-o5oJktTFuLdrWAsOdgK_h1qzcRm-0pCPvoAyketas1uJrA7QOmR-WKr6KA1kocY_oM4rSJyzRS0y6324Y_wAPBHof8K0_tfutZaxC01J4gcK3IFau9f8AOKtO2hztH__S-o0jPmFF4wWNc9rU5iRVHUnIFdYi8vjHOen1rz7xDOTqQgQ_dAQY9Wrx8Qz28HFJHodiDFYwHjIGf0_xrntU1WFY0tSdqk7j6n1rpZWSLTFwcYTAb2xivMb-6tLSzbVtQXdljgegBwqgfQVFRrY68LT5veN7SrpY7SXUZQI2l_1YbsucDPoSf0ryXX_E1vrN02n6dvMMbnc-OHYcbvf2HpUXiTxP4ikgS6s7BIbV2_dfapNrSsBydi_dVQOprJ8OeI2vGD3FnbmIrvSa0O-NwDtJB7_NxRKjJLWOhdCvTdS3Nqes-EoY9M0ieYjDP0_LiodNmjfMC7d85wTn0yMVpWwgurIQw_dI4x0NZTaWLCT90Ru61l2O9QT5r7mVrqebqz3AwUDlEx2VMAVsyaraNok1pI_R-R6fNXIavepDMEmySTz6VlyeJtDtbeVZBvCkbyBx79KunqzGtGMYxTexlzX1vaFxFIMbgy4_EY_GuvsLtLiFXzn5w4I9xg_rXna-J_Bs05tZLR7Z24zIuzP51fWb-xB9sspPMsmPzIOWU-39RROPKZqSqL3Wek2EpeCSB_4cjFQaKygGLIO1wuOn3v8AIqTTDG881xEcpJ5ci47hl5_lVbRRvu7xB_C24fg39KqDOSoiXVYPKu45e_Q_yqHePSt3X4sDdtyP_wBRrktyf3RWkjGL0P_T-rLqT7OjsODub9K8s1ObOrCcHIMikfgo_rXo2vY8lynGM_nXmGoqfLEg4KqT9PT-VeBiJH0mDhoej6rdiLRYQuSzJGB9T1_lXKPZfabeOG8QOIySvtmt7UmaWKy5yvlRn_x2qEscjDehxQ_iud-GilBHEaz4a1UWYi065_dkuFEq79okBV1BH8DjqD07VwyaNfaPp8lgBCg8swoFTy40QncdiDpluTXrk91Oo2nbxWD9njvJh5_z88AVr9YlsH1GlfmcdSz4Okvhp8AvmEkgHzPjG7AwGx2yOtTatfsbsoPp-FdBb28drDvIxt7VyGp-W1wJR3PPFYSOmmluc5rUEc6M7Kx2jIxx-FeSrLdQC5iiiQiR1MatzgLnjj8_rivdvIjl-VuQa4e90eCO4Z7b5cGt6dXlOWthlUVnscN4e0e8-0gXdu08Ucs0ubpg2_zV27C3P7sf3cV0UWg3en6e7xHfH0eIdMdsHqcdB7V1NlmNNqkk_SuhtflQhxwfaqq1-dWMsNgY0XeJj-C71Z7AwH78cSpz1wrED9DWxou6DXLmPGBIG5-p6flisG1Eem67IsX3J4_l-ua6HS3xrrNnGc9vasKLIxVPlOs10GSz3ei_yrg9yeld9qYJtZU45UVxX2Y11NdjhgrI_9T6j1BBNC8eOUk5rz7VohHZSZ9Qv4ZrvXLreTbvuk4A_GuJ8R4W0-X--BgV89X1PqMJpZG08ytY2D8fdCf4UrRO446dK5qW6CaKIc_NDtl_AnNdL9o2kccEA_nQnq0dlL4VY5nUYpY87a5_RLif-02hdeh4r0G9-zyw-YcdcCq9rpMEWZTgMe_pS5feOpVVyaouyROJHR5VztGIgRkfhXO31qqj5xgGq-teGNK1S7S_u2ZbiLBSWMlWGPcUmuP9ptxFFKQAAN3em0KnpazMyJTvyh-QYrlNXJN4QoA9AKvaXolto_mm1ldvNbc5kYsT-dTyRW5vPNYjBpTVlcum1ezItMgYoCRWncfImKsq0ESDaeKyrm4SQ4Bzip5tDTl10Oc1O4SG6trluCJNg_GupsSx1cEd8dK8y8Zz7JtPgXjMobj6gV6Pocvn39sB_FtNXRjZJnmY2SlJpdD0LV9iIU7hgp_AVzm6P0rS1e53ymP_AGi1Yu8e36V13PMSP__V-n9QAFyyL_Ex_LNcRrmJZoLePGZeeeMDoP0rtL5S927J_eKD6ZrzHX7yO3uLi_flYV2Rj3xivn6259PhvhRzV7rMUeuNppbHmwlc9v3S_LXqWjzpqOl29zGfvRr_AIf0r5X1u6afbeCQx3EZbn2PUV7H8GfEH9p6HNp07Zkspig_3G-Zf8KzpxbjdnXKSjLlXyO-v4p4biJwnmBVJVc4GazJPEFpbnF2rwMeCGGQPx6V2NwgcDP8NY11p0V2CHXNXy9jenOL-M5ifWNOlyUuFK46iubuNesh8kkyfhR4h8KQmPzYR5cqnkpxn6ivP20ba7b1yTxu_wAKnra56caFOVPmizsU1vTwSPPQegNQyanpchEPmo2_gBa5iDw_bySD92AB3Izmuut9Os4IfLiRVx7Vo0rbnDKKjoitbTXCNJbSEsq7Sj_7J7H3FTRhmcnPAqeGMx5TualaPYPrXO0XF6Hl_jmfy9VssdV5_WvT_DUmyWK4b-Bf_rV4b4t1JJ_GIthytskZb6lhx_Ova9NgltleOTjZxn2NdihaETxqk1KpM3bi682RGPG5TVfK-9VryIwxwyoPujP61W-2v6fyovYxsf_W-pLwrBbyzL95dyp_vscV4F4wlyhso-QGGT6kmvfNTjHkEHoCxr5_1iI3Fyz-rg_gK-exHxWPqMJ8NzzHV7fah_E_nx_SrXwxvLjR_FCbOY7r91IO3JypH0xWxq1sdjbRz0p-haWbe-S66FSNo98iiM_daNPZ-8mfTJIYbuxqsSY1OamWPzYRPCcEgHFVTdRYIPUUzdLsYOokuvHSuUuE2vlVUj_drrruYMh2gYrm7gYG4qBioaVzugny7GU6rn5U571Crc9Oac90gJGOlUZbuFORxQ5LZEcheHH7zvWFrurxaZZtcHl8YRfUnpVpJpLt_Lg4Hqa4Xx2oijSIHnvUwjeSRNWXJB2PEzNJc3N9eSkmR3DZ_wB09K-vtLZbywhuOv2i3WT81H9a-SbHYc8ehx9P_rV9aeF7VoNH0qN-gto1YHtvXoffivVxGlrHzeF1uaNwN9l5B6xIvPsRmue8v_aH6V2F5CttdIkudsuI_wAO39Kl_syz_vD9K5kzqaP_1_qDXmAt2_3iBXj1zbjezkcCvVNcOdsf_TRq417AzMUxwTXz1bWR9XhV7iOEvtPbYCR7_jXn_wDabx-I7SLdwsqr7HsQRX0Tf6dEZFiRRwM_jXz1478Nah4f1S312FC1sZQXbB-Q9s_U4rSFK5tKVo3R9QaVKTDgnsP5VHcWaTk9j7VxnhPxNp9_aJslG7gH69671ZFkztxxWa1VjR3i7oxbfRYwj78n8a57UdL6oGIFd680ew9iK5XUpFVTyKUkktDajOTepwF7Yp5JYMd6_KcdxWDHA7HGK6iaRGYjr7VB5I6gDNZpG7EsoxBHXlHjt3ZmP1xXsaxlY8ngCvH_AByJbm5i0vTE826nYxxovXJXr7YrajH34o5MU_3cjl_BVlb3d15ZiUxQDzJWYZPy9hX0_YW-zRbaROMgD_vk1594f8HxeG9G-zSmOSZolSTaT1YgHFen3c0NqsdmvCRhY8fQcn866q8tTz6VLkikV9Y23Noj_wAXB_EcGuW2P_tVq2l2XuzpspysiMB_vDt-Iq__AGV_sN-VRYz0Wh__0PoOWQXDlC2Srkj8yKuG1Hykkcdf61eg_wBef97-prfl-5-FeKqZ9Iq1rJIwre3i-1jONzgBavahoVpeW8kUihkddrg8gg9RitNP-PyL610B-631rspU1YwqYlpxsfIPiL4V6hpMxvvCTMqA5MDHoP8AYP8AQ1ylh8SNT0C7MGtIU28ENwf1r7N1n_j0b6V85fE__X23-5Wc8PGWp108XLkvY6HR_F-j6_CJLadAWHTIqO_eIodrhhXCeB_9afxr16X7grhnTs-U6qOL0ukeWsFQks4PP0qvNremWUW6edAR_DkV39__AKv8a88m_wCP6T6VpSw_NLluKeNtb3ShHq2r-IPKi0CDZE5wbmYbYlX1z3_CvR_Cvg2x8Plr6YtJqkq_vLs4K89owfujtXWeF_8AkXLD_rkK7KHon-6f512woxhsck8Q5bo808Qx7bUzsV3Aqc4A71wF1qJurpCSAqoT-Jr3XWv-PE_QV56f9b_wA1hWhqaRrLl2ODhuhDq0DuwXbIh5PHp_9avRv7dtf-esX51lXf8Aro_w_kaWkoHJKp5H_9k"
    const val SIGNATURE_OR_USUAL_MARK_BASE64URL = "_9j_4AAQSkZJRgABAQIAOAA4AAD_4g_wSUNDX1BST0ZJTEUAAQEAAA_gYXBwbAIQAABtbnRyUkdCIFhZWiAH5gAIAB4ACAAsAB1hY3NwQVBQTAAAAABBUFBMAAAAAAAAAAAAAAAAAAAAAAAA9tYAAQAAAADTLWFwcGwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJkZXNjAAABXAAAAGJkc2NtAAABwAAABIJjcHJ0AAAGRAAAACN3dHB0AAAGaAAAABRyWFlaAAAGfAAAABRnWFlaAAAGkAAAABRiWFlaAAAGpAAAABRyVFJDAAAGuAAACAxhYXJnAAAOxAAAACB2Y2d0AAAO5AAAADBuZGluAAAPFAAAAD5jaGFkAAAPVAAAACxtbW9kAAAPgAAAACh2Y2dwAAAPqAAAADhiVFJDAAAGuAAACAxnVFJDAAAGuAAACAxhYWJnAAAOxAAAACBhYWdnAAAOxAAAACBkZXNjAAAAAAAAAAhEaXNwbGF5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbWx1YwAAAAAAAAAmAAAADGhySFIAAAAUAAAB2GtvS1IAAAAMAAAB7G5iTk8AAAASAAAB-GlkAAAAAAASAAACCmh1SFUAAAAUAAACHGNzQ1oAAAAWAAACMGRhREsAAAAcAAACRm5sTkwAAAAWAAACYmZpRkkAAAAQAAACeGl0SVQAAAAUAAACiGVzRVMAAAASAAACnHJvUk8AAAASAAACnGZyQ0EAAAAWAAACrmFyAAAAAAAUAAACxHVrVUEAAAAcAAAC2GhlSUwAAAAWAAAC9HpoVFcAAAAKAAADCnZpVk4AAAAOAAADFHNrU0sAAAAWAAADInpoQ04AAAAKAAADCnJ1UlUAAAAkAAADOGVuR0IAAAAUAAADXGZyRlIAAAAWAAADcG1zAAAAAAASAAADhmhpSU4AAAASAAADmHRoVEgAAAAMAAADqmNhRVMAAAAYAAADtmVuQVUAAAAUAAADXGVzWEwAAAASAAACnGRlREUAAAAQAAADzmVuVVMAAAASAAAD3nB0QlIAAAAYAAAD8HBsUEwAAAASAAAECGVsR1IAAAAiAAAEGnN2U0UAAAAQAAAEPHRyVFIAAAAUAAAETHB0UFQAAAAWAAAEYGphSlAAAAAMAAAEdgBMAEMARAAgAHUAIABiAG8AagBpzuy37AAgAEwAQwBEAEYAYQByAGcAZQAtAEwAQwBEAEwAQwBEACAAVwBhAHIAbgBhAFMAegDtAG4AZQBzACAATABDAEQAQgBhAHIAZQB2AG4A_QAgAEwAQwBEAEwAQwBEAC0AZgBhAHIAdgBlAHMAawDmAHIAbQBLAGwAZQB1AHIAZQBuAC0ATABDAEQAVgDkAHIAaQAtAEwAQwBEAEwAQwBEACAAYwBvAGwAbwByAGkATABDAEQAIABjAG8AbABvAHIAQQBDAEwAIABjAG8AdQBsAGUAdQByIA8ATABDAEQAIAZFBkQGSAZGBikEGgQ-BDsETAQ-BEAEPgQyBDgEOQAgAEwAQwBEIA8ATABDAEQAIAXmBdEF4gXVBeAF2V9pgnIATABDAEQATABDAEQAIABNAOAAdQBGAGEAcgBlAGIAbgD9ACAATABDAEQEJgQyBDUEQgQ9BD4EOQAgBBYEGgAtBDQEOARBBD8EOwQ1BDkAQwBvAGwAbwB1AHIAIABMAEMARABMAEMARAAgAGMAbwB1AGwAZQB1AHIAVwBhAHIAbgBhACAATABDAEQJMAkCCRcJQAkoACAATABDAEQATABDAEQAIA4qDjUATABDAEQAIABlAG4AIABjAG8AbABvAHIARgBhAHIAYgAtAEwAQwBEAEMAbwBsAG8AcgAgAEwAQwBEAEwAQwBEACAAQwBvAGwAbwByAGkAZABvAEsAbwBsAG8AcgAgAEwAQwBEA4gDswPHA8EDyQO8A7cAIAO_A7gDzAO9A7cAIABMAEMARABGAOQAcgBnAC0ATABDAEQAUgBlAG4AawBsAGkAIABMAEMARABMAEMARAAgAGEAIABDAG8AcgBlAHMwqzDpMPwATABDAEQAAHRleHQAAAAAQ29weXJpZ2h0IEFwcGxlIEluYy4sIDIwMjIAAFhZWiAAAAAAAADzFgABAAAAARbKWFlaIAAAAAAAAHHAAAA5igAAAWdYWVogAAAAAAAAYSMAALnmAAAT9lhZWiAAAAAAAAAj8gAADJAAAL3QY3VydgAAAAAAAAQAAAAABQAKAA8AFAAZAB4AIwAoAC0AMgA2ADsAQABFAEoATwBUAFkAXgBjAGgAbQByAHcAfACBAIYAiwCQAJUAmgCfAKMAqACtALIAtwC8AMEAxgDLANAA1QDbAOAA5QDrAPAA9gD7AQEBBwENARMBGQEfASUBKwEyATgBPgFFAUwBUgFZAWABZwFuAXUBfAGDAYsBkgGaAaEBqQGxAbkBwQHJAdEB2QHhAekB8gH6AgMCDAIUAh0CJgIvAjgCQQJLAlQCXQJnAnECegKEAo4CmAKiAqwCtgLBAssC1QLgAusC9QMAAwsDFgMhAy0DOANDA08DWgNmA3IDfgOKA5YDogOuA7oDxwPTA-AD7AP5BAYEEwQgBC0EOwRIBFUEYwRxBH4EjASaBKgEtgTEBNME4QTwBP4FDQUcBSsFOgVJBVgFZwV3BYYFlgWmBbUFxQXVBeUF9gYGBhYGJwY3BkgGWQZqBnsGjAadBq8GwAbRBuMG9QcHBxkHKwc9B08HYQd0B4YHmQesB78H0gflB_gICwgfCDIIRghaCG4IggiWCKoIvgjSCOcI-wkQCSUJOglPCWQJeQmPCaQJugnPCeUJ-woRCicKPQpUCmoKgQqYCq4KxQrcCvMLCwsiCzkLUQtpC4ALmAuwC8gL4Qv5DBIMKgxDDFwMdQyODKcMwAzZDPMNDQ0mDUANWg10DY4NqQ3DDd4N-A4TDi4OSQ5kDn8Omw62DtIO7g8JDyUPQQ9eD3oPlg-zD88P7BAJECYQQxBhEH4QmxC5ENcQ9RETETERTxFtEYwRqhHJEegSBxImEkUSZBKEEqMSwxLjEwMTIxNDE2MTgxOkE8UT5RQGFCcUSRRqFIsUrRTOFPAVEhU0FVYVeBWbFb0V4BYDFiYWSRZsFo8WshbWFvoXHRdBF2UXiReuF9IX9xgbGEAYZRiKGK8Y1Rj6GSAZRRlrGZEZtxndGgQaKhpRGncanhrFGuwbFBs7G2MbihuyG9ocAhwqHFIcexyjHMwc9R0eHUcdcB2ZHcMd7B4WHkAeah6UHr4e6R8THz4faR-UH78f6iAVIEEgbCCYIMQg8CEcIUghdSGhIc4h-yInIlUigiKvIt0jCiM4I2YjlCPCI_AkHyRNJHwkqyTaJQklOCVoJZclxyX3JicmVyaHJrcm6CcYJ0kneierJ9woDSg_KHEooijUKQYpOClrKZ0p0CoCKjUqaCqbKs8rAis2K2krnSvRLAUsOSxuLKIs1y0MLUEtdi2rLeEuFi5MLoIuty7uLyQvWi-RL8cv_jA1MGwwpDDbMRIxSjGCMbox8jIqMmMymzLUMw0zRjN_M7gz8TQrNGU0njTYNRM1TTWHNcI1_TY3NnI2rjbpNyQ3YDecN9c4FDhQOIw4yDkFOUI5fzm8Ofk6Njp0OrI67zstO2s7qjvoPCc8ZTykPOM9Ij1hPaE94D4gPmA-oD7gPyE_YT-iP-JAI0BkQKZA50EpQWpBrEHuQjBCckK1QvdDOkN9Q8BEA0RHRIpEzkUSRVVFmkXeRiJGZ0arRvBHNUd7R8BIBUhLSJFI10kdSWNJqUnwSjdKfUrESwxLU0uaS-JMKkxyTLpNAk1KTZNN3E4lTm5Ot08AT0lPk0_dUCdQcVC7UQZRUFGbUeZSMVJ8UsdTE1NfU6pT9lRCVI9U21UoVXVVwlYPVlxWqVb3V0RXklfgWC9YfVjLWRpZaVm4WgdaVlqmWvVbRVuVW-VcNVyGXNZdJ114XcleGl5sXr1fD19hX7NgBWBXYKpg_GFPYaJh9WJJYpxi8GNDY5dj62RAZJRk6WU9ZZJl52Y9ZpJm6Gc9Z5Nn6Wg_aJZo7GlDaZpp8WpIap9q92tPa6dr_2xXbK9tCG1gbbluEm5rbsRvHm94b9FwK3CGcOBxOnGVcfByS3KmcwFzXXO4dBR0cHTMdSh1hXXhdj52m3b4d1Z3s3gReG54zHkqeYl553pGeqV7BHtje8J8IXyBfOF9QX2hfgF-Yn7CfyN_hH_lgEeAqIEKgWuBzYIwgpKC9INXg7qEHYSAhOOFR4Wrhg6GcobXhzuHn4gEiGmIzokziZmJ_opkisqLMIuWi_yMY4zKjTGNmI3_jmaOzo82j56QBpBukNaRP5GokhGSepLjk02TtpQglIqU9JVflcmWNJaflwqXdZfgmEyYuJkkmZCZ_JpomtWbQpuvnByciZz3nWSd0p5Anq6fHZ-Ln_qgaaDYoUehtqImopajBqN2o-akVqTHpTilqaYapoum_adup-CoUqjEqTepqaocqo-rAqt1q-msXKzQrUStuK4trqGvFq-LsACwdbDqsWCx1rJLssKzOLOutCW0nLUTtYq2AbZ5tvC3aLfguFm40blKucK6O7q1uy67p7whvJu9Fb2Pvgq-hL7_v3q_9cBwwOzBZ8Hjwl_C28NYw9TEUcTOxUvFyMZGxsPHQce_yD3IvMk6ybnKOMq3yzbLtsw1zLXNNc21zjbOts83z7jQOdC60TzRvtI_0sHTRNPG1EnUy9VO1dHWVdbY11zX4Nhk2OjZbNnx2nba-9uA3AXcit0Q3ZbeHN6i3ynfr-A24L3hROHM4lPi2-Nj4-vkc-T85YTmDeaW5x_nqegy6LzpRunQ6lvq5etw6_vshu0R7ZzuKO6070DvzPBY8OXxcvH_8ozzGfOn9DT0wvVQ9d72bfb794r4Gfio-Tj5x_pX-uf7d_wH_Jj9Kf26_kv-3P9t__9wYXJhAAAAAAADAAAAAmZmAADypwAADVkAABPQAAAKW3ZjZ3QAAAAAAAAAAQABAAAAAAAAAAEAAAABAAAAAAAAAAEAAAABAAAAAAAAAAEAAG5kaW4AAAAAAAAANgAAp0AAAFWAAABMwAAAnsAAACWAAAAMwAAAUAAAAFRAAAIzMwACMzMAAjMzAAAAAAAAAABzZjMyAAAAAAABDHIAAAX4___zHQAAB7oAAP1y___7nf___aQAAAPZAADAcW1tb2QAAAAAAAAGEAAAoC8AAAAA0OXf8AAAAAAAAAAAAAAAAAAAAAB2Y2dwAAAAAAADAAAAAmZmAAMAAAACZmYAAwAAAAJmZgAAAAIzMzQAAAAAAjMzNAAAAAACMzM0AP_bAEMABQMEBAQDBQQEBAUFBQYHDAgHBwcHDwsLCQwRDxISEQ8RERMWHBcTFBoVEREYIRgaHR0fHx8TFyIkIh4kHB4fHv_AAAsIADcAeAEBEQD_xAAfAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgv_xAC1EAACAQMDAgQDBQUEBAAAAX0BAgMABBEFEiExQQYTUWEHInEUMoGRoQgjQrHBFVLR8CQzYnKCCQoWFxgZGiUmJygpKjQ1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4eLj5OXm5-jp6vHy8_T19vf4-fr_2gAIAQEAAD8A-y6KM0UUUUUUUUUUUUVzN7qGt6zeTWPh1oLO1gdorjVJ4_M-ccMkMeQGYHgux2qeMOQwEkPhGzILX-qa5qExOTLLqcsf5JEURfwUUeEJnF_rGnRXk99Y2U6RxTTv5jo5XMkW88uE-Xk5ILFSTt46KiiiiiiiiiiiuN02-u_CFt_ZmradcS6VAW8jU7VDKojJJAnjX50YZ5cBlONxK5wOssbq1vrSK7sriG5tplDxSxOHR1PQgjgj3qsH03RoLSyiiW2ilm8mCOKI7d5DN_COM4Y5OBnvk1eLKMZIGeBmkikjlTfG6uuSMqcjg4P61Ct9ZtPHALuAyy7vLQSDc-04bAzzjvjpU7MqjLEAe9NuI_Nt5IhI8e9Su9Dhlz3B9a4KxsdZ1LxbeT6X4hm-xaKfssS30QuI5LllBlPylGIRSiAljy0npXVaJHrBuZpdU1SyuAg8sQWluY1RupLFmZi2MccAA985rWpkMscyCSJ1dD0ZTkGnBgSQCMjqKWioL-7tbG0kuryeO3gjGXkkbaq_jXn_AILGpTeIfFEPhuJdM0Z72OQPdwtlLhog0_lQ8bQ2Y2O4jDs5Kkk1pDTtc0rxfPqKLquuK-npBbGW8jjhjlMjGUuvATIEWCqMcA9-tTWNB8m_GueK9aW6eTZHDbQWp3RvyfKtsEtljglgPMOPvKoAWpp9p4kuvB-sSaAq6VFNc3P9m2UBQOrFtgLyDKxqHDOQgJxnDZ4q2nhBtBbw9_ZmmnU5LAs89wWRJHkWFo4wWY5WP95IxC7jnnDFmJuar4R1XWr2K-1jVoH2RsEsVtg8EDE_eTf1kx8u91bAJ2qmTmr4Qg8Rad4LtNItrK-hvIYC99f6i4llknOWkKDcTIxcnBYhQMfextqHwVdXqeCtM0Xw6xvNRa3Et_qdwpaGKeT95KzHjzJS7N8i9D97bwDFpdj4qtPh7Lovh6ynsNY-ySyXOp3_AJZea9dSXdVBId2kJO5sIBjAYDbV7VIvFdx4NbSPDFvdaS8dqltDeX8iyXO44Tfjcw-XJdnYknBAUkgi_pnguHQ9NWHQdS1GznS2ETHzw6Tsq4VnWRWVTxyVAOOOgFY3gjw5q-l28htra9g1S8iT-0dV1a5WeR5OSxjjRiD8xOMlVUYABAC132n232SzitvPnnMa4Msz7nc9yT6n2wPQAVPXAWGoP4hdNQs_Lv8AUZCWtI2G620pCSA8uODNjkr97J2jau5j2WiabBpWmx2cBd9pLSSOcvK7El3Y92ZiSfrSa5qcGlac93MryHISKKMZeaRjhUUdyTx6dzgAmuR1v7fafZ4xKk3i_Wg0FqyjdHp8XBldAeiRqQS3WRygONyhey0mxt9M0u2060UrBbRLFGCcnaowMnueOTVqiiiiiiiiigADoKK5XxLJew-J7W6TSb3Ult7VjYxQgBDcOSrM7k4TanAY9nfAJ4q34X0KayuLjWNXmju9bvQFnlQHy4YwSVgiB5Ea5JyeWYlj1AG_RRRRRRRRRRRRRRRRRRRRRRRRX__Z"
    const val AGE_IN_YEARS = 54
    const val AGE_BIRTH_YEAR = 1971
    const val AGE_OVER = true  // Generic "age over" value
    const val AGE_OVER_13 = true
    const val AGE_OVER_16 = true
    const val AGE_OVER_18 = true
    const val AGE_OVER_21 = true
    const val AGE_OVER_25 = true
    const val AGE_OVER_60 = false
    const val AGE_OVER_62 = false
    const val AGE_OVER_65 = false
    const val AGE_OVER_68 = false
    const val ISSUING_JURISDICTION = "State of Utopia"
    const val NATIONALITY = "ZZ"         // Note: ZZ is a user-assigned country-code as per ISO 3166-1
    const val SECOND_NATIONALITY = "XZ"  // Note: XZ is a user-assigned country-code as per ISO 3166-1
    const val RESIDENT_STREET = "Sample Street"
    const val RESIDENT_HOUSE_NUMBER = "123"
    const val RESIDENT_POSTAL_CODE = "12345"
    const val RESIDENT_CITY = "Sample City"
    const val RESIDENT_STATE = "Sample State"
    const val RESIDENT_COUNTRY = "ZZ"  // Note: ZZ is a user-assigned country-code as per ISO 3166-1
    const val EMAIL_ADDRESS = "erika.mustermann@example.com"
    const val MOBILE_PHONE_NUMBER = "+155555555555"

}

/**
 * Object containing the metadata of the Driving License
 * Document Type.
 */
object DrivingLicense {
    const val MDL_DOCTYPE = "org.iso.18013.5.1.mDL"
    const val MDL_NAMESPACE = "org.iso.18013.5.1"
    const val AAMVA_NAMESPACE = "org.iso.18013.5.1.aamva"

    /**
     * Build the Driving License Document Type. This is ISO mdoc only.
     */
    fun getDocumentType(): DocumentType {
        return DocumentType.Builder("Driving License")
            .addMdocDocumentType(MDL_DOCTYPE)
            /*
             * First the attributes that the mDL and VC Credential Type have in common
             */
            .addMdocAttribute(
                DocumentAttributeType.String,
                "family_name",
                "Family Name",
                "Last name, surname, or primary identifier, of the mDL holder.",
                true,
                MDL_NAMESPACE,
                Icon.PERSON,
                SampleData.FAMILY_NAME.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "given_name",
                "Given Names",
                "First name(s), other name(s), or secondary identifier, of the mDL holder",
                true,
                MDL_NAMESPACE,
                Icon.PERSON,
                SampleData.GIVEN_NAME.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Date,
                "birth_date",
                "Date of Birth",
                "Day, month and year on which the mDL holder was born. If unknown, approximate date of birth",
                true,
                MDL_NAMESPACE,
                Icon.TODAY,
                LocalDate.parse(SampleData.BIRTH_DATE).toDataItemFullDate()
            )
            .addMdocAttribute(
                DocumentAttributeType.Date,
                "issue_date",
                "Date of Issue",
                "Date when mDL was issued",
                true,
                MDL_NAMESPACE,
                Icon.DATE_RANGE,
                LocalDate.parse(SampleData.ISSUE_DATE).toDataItemFullDate()
            )
            .addMdocAttribute(
                DocumentAttributeType.Date,
                "expiry_date",
                "Date of Expiry",
                "Date when mDL expires",
                true,
                MDL_NAMESPACE,
                Icon.CALENDAR_CLOCK,
                LocalDate.parse(SampleData.EXPIRY_DATE).toDataItemFullDate()
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(Options.COUNTRY_ISO_3166_1_ALPHA_2),
                "issuing_country",
                "Issuing Country",
                "Alpha-2 country code, as defined in ISO 3166-1, of the issuing authority’s country or territory",
                true,
                MDL_NAMESPACE,
                Icon.ACCOUNT_BALANCE,
                SampleData.ISSUING_COUNTRY.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "issuing_authority",
                "Issuing Authority",
                "Issuing authority name.",
                true,
                MDL_NAMESPACE,
                Icon.ACCOUNT_BALANCE,
                SampleData.ISSUING_AUTHORITY_MDL.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "document_number",
                "License Number",
                "The number assigned or calculated by the issuing authority.",
                true,
                MDL_NAMESPACE,
                Icon.NUMBERS,
                SampleData.DOCUMENT_NUMBER.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Picture,
                "portrait",
                "Photo of Holder",
                "A reproduction of the mDL holder’s portrait.",
                true,
                MDL_NAMESPACE,
                Icon.ACCOUNT_BOX,
                SampleData.PORTRAIT_BASE64URL.fromBase64Url().toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.ComplexType,
                "driving_privileges",
                "Driving Privileges",
                "Driving privileges of the mDL holder",
                true,
                MDL_NAMESPACE,
                Icon.DIRECTIONS_CAR,
                buildCborArray {
                    addCborMap {
                        put("vehicle_category_code", "A")
                        put("issue_date", Tagged(1004, Tstr("2018-08-09")))
                        put("expiry_date", Tagged(1004, Tstr("2028-09-01")))
                    }
                    addCborMap {
                        put("vehicle_category_code", "B")
                        put("issue_date", Tagged(1004, Tstr("2017-02-23")))
                        put("expiry_date", Tagged(1004, Tstr("2028-09-01")))
                    }
                }
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(Options.DISTINGUISHING_SIGN_ISO_IEC_18013_1_ANNEX_F),
                "un_distinguishing_sign",
                "UN Distinguishing Sign",
                "Distinguishing sign of the issuing country",
                true,
                MDL_NAMESPACE,
                Icon.LANGUAGE,
                SampleData.UN_DISTINGUISHING_SIGN.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "administrative_number",
                "Administrative Number",
                "An audit control number assigned by the issuing authority",
                false,
                MDL_NAMESPACE,
                Icon.NUMBERS,
                SampleData.ADMINISTRATIVE_NUMBER.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.IntegerOptions(Options.SEX_ISO_IEC_5218),
                "sex",
                "Sex",
                "mDL holder’s sex",
                false,
                MDL_NAMESPACE,
                Icon.EMERGENCY,
                SampleData.SEX_ISO218.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Number,
                "height",
                "Height",
                "mDL holder’s height in centimetres",
                false,
                MDL_NAMESPACE,
                Icon.EMERGENCY,
                SampleData.HEIGHT_CM.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Number,
                "weight",
                "Weight",
                "mDL holder’s weight in kilograms",
                false,
                MDL_NAMESPACE,
                Icon.EMERGENCY,
                SampleData.WEIGHT_KG.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(
                    listOf(
                        StringOption(null, "(not set)"),
                        StringOption("black", "Black"),
                        StringOption("blue", "Blue"),
                        StringOption("brown", "Brown"),
                        StringOption("dichromatic", "Dichromatic"),
                        StringOption("grey", "Grey"),
                        StringOption("green", "Green"),
                        StringOption("hazel", "Hazel"),
                        StringOption("maroon", "Maroon"),
                        StringOption("pink", "Pink"),
                        StringOption("unknown", "Unknown")
                    )
                ),
                "eye_colour",
                "Eye Color",
                "mDL holder’s eye color",
                false,
                MDL_NAMESPACE,
                Icon.PERSON,
                "blue".toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(
                    listOf(
                        StringOption(null, "(not set)"),
                        StringOption("bald", "Bald"),
                        StringOption("black", "Black"),
                        StringOption("blond", "Blond"),
                        StringOption("brown", "Brown"),
                        StringOption("grey", "Grey"),
                        StringOption("red", "Red"),
                        StringOption("auburn", "Auburn"),
                        StringOption("sandy", "Sandy"),
                        StringOption("white", "White"),
                        StringOption("unknown", "Unknown"),
                    )
                ),
                "hair_colour",
                "Hair Color",
                "mDL holder’s hair color",
                false,
                MDL_NAMESPACE,
                Icon.PERSON,
                "blond".toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "birth_place",
                "Place of Birth",
                "Country and municipality or state/province where the mDL holder was born",
                false,
                MDL_NAMESPACE,
                Icon.PLACE,
                SampleData.BIRTH_PLACE.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "resident_address",
                "Resident Address",
                "The place where the mDL holder resides and/or may be contacted (street/house number, municipality etc.)",
                false,
                MDL_NAMESPACE,
                Icon.PLACE,
                SampleData.RESIDENT_ADDRESS.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Date,
                "portrait_capture_date",
                "Portrait Image Timestamp",
                "Date when portrait was taken",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                LocalDate.parse(SampleData.PORTRAIT_CAPTURE_DATE).toDataItemFullDate()
            )
            .addMdocAttribute(
                DocumentAttributeType.Number,
                "age_in_years",
                "Age in Years",
                "The age of the mDL holder",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_IN_YEARS.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Number,
                "age_birth_year",
                "Year of Birth",
                "The year when the mDL holder was born",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_BIRTH_YEAR.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_13",
                "Older Than 13 Years",
                "Indication whether the mDL holder is as old or older than 13",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_13.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_16",
                "Older Than 16 Years",
                "Indication whether the mDL holder is as old or older than 16",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_16.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_18",
                "Older Than 18 Years",
                "Indication whether the mDL holder is as old or older than 18",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_18.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_21",
                "Older Than 21 Years",
                "Indication whether the mDL holder is as old or older than 21",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_21.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_25",
                "Older Than 25 Years",
                "Indication whether the mDL holder is as old or older than 25",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_25.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_60",
                "Older Than 60 Years",
                "Indication whether the mDL holder is as old or older than 60",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_60.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_62",
                "Older Than 62 Years",
                "Indication whether the mDL holder is as old or older than 62",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_62.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_65",
                "Older Than 65 Years",
                "Indication whether the mDL holder is as old or older than 65",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_65.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Boolean,
                "age_over_68",
                "Older Than 68 Years",
                "Indication whether the mDL holder is as old or older than 68",
                false,
                MDL_NAMESPACE,
                Icon.TODAY,
                SampleData.AGE_OVER_68.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "issuing_jurisdiction",
                "Issuing Jurisdiction",
                "Country subdivision code of the jurisdiction that issued the mDL",
                false,
                MDL_NAMESPACE,
                Icon.ACCOUNT_BALANCE,
                SampleData.ISSUING_JURISDICTION.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(Options.COUNTRY_ISO_3166_1_ALPHA_2),
                "nationality",
                "Nationality",
                "Nationality of the mDL holder",
                false,
                MDL_NAMESPACE,
                Icon.LANGUAGE,
                SampleData.NATIONALITY.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "resident_city",
                "Resident City",
                "The city where the mDL holder lives",
                false,
                MDL_NAMESPACE,
                Icon.PLACE,
                SampleData.RESIDENT_CITY.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "resident_state",
                "Resident State",
                "The state/province/district where the mDL holder lives",
                false,
                MDL_NAMESPACE,
                Icon.PLACE,
                SampleData.RESIDENT_STATE.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "resident_postal_code",
                "Resident Postal Code",
                "The postal code of the mDL holder",
                false,
                MDL_NAMESPACE,
                Icon.PLACE,
                SampleData.RESIDENT_POSTAL_CODE.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(Options.COUNTRY_ISO_3166_1_ALPHA_2),
                "resident_country",
                "Resident Country",
                "The country where the mDL holder lives",
                false,
                MDL_NAMESPACE,
                Icon.PLACE,
                SampleData.RESIDENT_COUNTRY.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "family_name_national_character",
                "Family Name National Characters",
                "The family name of the mDL holder",
                false,
                MDL_NAMESPACE,
                Icon.PERSON,
                SampleData.FAMILY_NAME_NATIONAL_CHARACTER.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "given_name_national_character",
                "Given Name National Characters",
                "The given name of the mDL holder",
                false,
                MDL_NAMESPACE,
                Icon.PERSON,
                SampleData.GIVEN_NAMES_NATIONAL_CHARACTER.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.Picture,
                "signature_usual_mark",
                "Signature / Usual Mark",
                "Image of the signature or usual mark of the mDL holder,",
                false,
                MDL_NAMESPACE,
                Icon.SIGNATURE,
                SampleData.SIGNATURE_OR_USUAL_MARK_BASE64URL.fromBase64Url().toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.ComplexType,
                "domestic_driving_privileges",
                "Domestic Driving Privileges",
                "Vehicle types the license holder is authorized to operate",
                false,
                AAMVA_NAMESPACE,
                Icon.DIRECTIONS_CAR,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(Options.AAMVA_NAME_SUFFIX),
                "name_suffix",
                "Name Suffix",
                "Name suffix of the individual that has been issued the driver license or identification document.",
                false,
                AAMVA_NAMESPACE,
                Icon.PERSON,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.IntegerOptions(
                    listOf(
                        IntegerOption(null, "(not set)"),
                        IntegerOption(1, "Donor")
                    )
                ),
                "organ_donor",
                "Organ Donor",
                "An indicator that denotes whether the credential holder is an organ donor.",
                false,
                AAMVA_NAMESPACE,
                Icon.EMERGENCY,
                1.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.IntegerOptions(
                    listOf(
                        IntegerOption(null, "(not set)"),
                        IntegerOption(1, "Veteran")
                    )
                ),
                "veteran",
                "Veteran",
                "An indicator that denotes whether the credential holder is a veteran.",
                false,
                AAMVA_NAMESPACE,
                Icon.MILITARY_TECH,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(
                    listOf(
                        StringOption(null, "(not set)"),
                        StringOption("T", "Truncated"),
                        StringOption("N", "Not truncated"),
                        StringOption("U", "Unknown whether truncated"),
                    )
                ),
                "family_name_truncation",
                "Family Name Truncation",
                "A code that indicates whether the field has been truncated",
                true,
                AAMVA_NAMESPACE,
                Icon.PERSON,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(
                    listOf(
                        StringOption(null, "(not set)"),
                        StringOption("T", "Truncated"),
                        StringOption("N", "Not truncated"),
                        StringOption("U", "Unknown whether truncated"),
                    )
                ),
                "given_name_truncation",
                "Given Name Truncation",
                "A code that indicates whether either the first name or the middle name(s) have been truncated",
                true,
                AAMVA_NAMESPACE,
                Icon.PERSON,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "aka_family_name",
                "Alias / AKA Family Name",
                "Other family name by which credential holder is known.",
                false,
                AAMVA_NAMESPACE,
                Icon.PERSON,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "aka_given_name",
                "Alias / AKA Given Name",
                "Other given name by which credential holder is known.",
                false,
                AAMVA_NAMESPACE,
                Icon.PERSON,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(Options.AAMVA_NAME_SUFFIX),
                "aka_suffix",
                "Alias / AKA Suffix Name",
                "Other suffix by which credential holder is known.",
                false,
                AAMVA_NAMESPACE,
                Icon.PERSON,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.IntegerOptions(
                    listOf(
                        IntegerOption(null, "(not set)"),
                        IntegerOption(0, "Up to 31 kg (up to 70 lbs.)"),
                        IntegerOption(1, "32 – 45 kg (71 – 100 lbs.)"),
                        IntegerOption(2, "46 - 59 kg (101 – 130 lbs.)"),
                        IntegerOption(3, "60 - 70 kg (131 – 160 lbs.)"),
                        IntegerOption(4, "71 - 86 kg (161 – 190 lbs.)"),
                        IntegerOption(5, "87 - 100 kg (191 – 220 lbs.)"),
                        IntegerOption(6, "101 - 113 kg (221 – 250 lbs.)"),
                        IntegerOption(7, "114 - 127 kg (251 – 280 lbs.)"),
                        IntegerOption(8, "128 – 145 kg (281 – 320 lbs.)"),
                        IntegerOption(9, "146+ kg (321+ lbs.)"),
                    )
                ),
                "weight_range",
                "Weight Range",
                "Indicates the approximate weight range of the cardholder",
                false,
                AAMVA_NAMESPACE,
                Icon.EMERGENCY,
                3.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(
                    listOf(
                        StringOption(null, "(not set)"),
                        StringOption("AI", "Alaskan or American Indian"),
                        StringOption("AP", "Asian or Pacific Islander"),
                        StringOption("BK", "Black"),
                        StringOption("H", "Hispanic Origin"),
                        StringOption("O", "Non-hispanic"),
                        StringOption("U", "Unknown"),
                        StringOption("W", "White")
                    )
                ),
                "race_ethnicity",
                "Race / Ethnicity",
                "Codes for race or ethnicity of the cardholder",
                false,
                AAMVA_NAMESPACE,
                Icon.EMERGENCY,
                "W".toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.StringOptions(
                    listOf(
                        StringOption(null, "(not set)"),
                        StringOption("F", "Fully compliant"),
                        StringOption("N", "Non-compliant"),
                    )
                ),
                "DHS_compliance",
                "Compliance Type",
                "DHS required field that indicates compliance",
                false,
                AAMVA_NAMESPACE,
                Icon.STARS,
                "F".toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.IntegerOptions(
                    listOf(
                        IntegerOption(null, "(not set)"),
                        IntegerOption(1, "Temporary lawful status")
                    )
                ),
                "DHS_temporary_lawful_status",
                "Limited Duration Document Indicator",
                "DHS required field that denotes whether the credential holder has temporary lawful status. 1: Temporary lawful status",
                false,
                AAMVA_NAMESPACE,
                Icon.STARS,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.IntegerOptions(
                    listOf(
                        IntegerOption(null, "(not set)"),
                        IntegerOption(1, "Driver's license"),
                        IntegerOption(2, "Identification card")
                    )
                ),
                "EDL_credential",
                "EDL Indicator",
                "Present if the credential is an EDL",
                false,
                AAMVA_NAMESPACE,
                Icon.DIRECTIONS_CAR,
                1.toDataItem()
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "resident_county",
                "Resident County",
                "The 3-digit county code of the county where the mDL holder lives",
                false,
                AAMVA_NAMESPACE,
                Icon.PLACE,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.Date,
                "hazmat_endorsement_expiration_date",
                "HAZMAT Endorsement Expiration Date",
                "Date on which the hazardous material endorsement granted by the document is no longer valid.",
                true,
                AAMVA_NAMESPACE,
                Icon.CALENDAR_CLOCK,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.IntegerOptions(Options.SEX_ISO_IEC_5218),
                "sex",
                "Sex",
                "mDL holder’s sex",
                true,
                AAMVA_NAMESPACE,
                Icon.EMERGENCY,
                SampleData.SEX_ISO218.toDataItem()
            )
            /*
             * Then the attributes that exist only in the mDL Credential Type and not in the VC Credential Type
             */
            .addMdocAttribute(
                DocumentAttributeType.Picture,
                "biometric_template_face",
                "Biometric Template Face",
                "Facial biometric information of the mDL holder",
                false,
                MDL_NAMESPACE,
                Icon.FACE,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.Picture,
                "biometric_template_finger",
                "Biometric Template Fingerprint",
                "Fingerprint of the mDL holder",
                false,
                MDL_NAMESPACE,
                Icon.FINGERPRINT,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.Picture,
                "biometric_template_signature_sign",
                "Biometric Template Signature/Sign",
                "Signature/sign of the mDL holder",
                false,
                MDL_NAMESPACE,
                Icon.SIGNATURE,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.Picture,
                "biometric_template_iris",
                "Biometric Template Iris",
                "Iris of the mDL holder",
                false,
                MDL_NAMESPACE,
                Icon.EYE_TRACKING,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.String,
                "audit_information",
                "Audit Information",
                "A string of letters and/or numbers that identifies when, where, and by whom the credential was initially provisioned.",
                false,
                AAMVA_NAMESPACE,
                Icon.STARS,
                null
            )
            .addMdocAttribute(
                DocumentAttributeType.Number,
                "aamva_version",
                "AAMVA Version Number",
                "A number identifying the version of the AAMVA mDL data element set",
                true,
                AAMVA_NAMESPACE,
                Icon.NUMBERS,
                null
            )
            .addSampleRequest(
                id = "us-transportation",
                displayName = "US Transportation",
                mdocDataElements = mapOf(
                    MDL_NAMESPACE to mapOf(
                        "sex" to false,
                        "portrait" to false,
                        "given_name" to false,
                        "issue_date" to false,
                        "expiry_date" to false,
                        "family_name" to false,
                        "document_number" to false,
                        "issuing_authority" to false
                    ),
                    AAMVA_NAMESPACE to mapOf(
                        "DHS_compliance" to false,
                        "EDL_credential" to false
                    ),
                )
            )
            .addSampleRequest(
                id = "age_over_18",
                displayName = "Age Over 18",
                mdocDataElements = mapOf(
                    MDL_NAMESPACE to mapOf(
                        "age_over_18" to false,
                    )
                ),
            )
            .addSampleRequest(
                id = "age_over_21",
                displayName = "Age Over 21",
                mdocDataElements = mapOf(
                    MDL_NAMESPACE to mapOf(
                        "age_over_21" to false,
                    )
                ),
            )
            .addSampleRequest(
                id = "age_over_18_and_portrait",
                displayName = "Age Over 18 + Portrait",
                mdocDataElements = mapOf(
                    MDL_NAMESPACE to mapOf(
                        "age_over_18" to false,
                        "portrait" to false
                    )
                ),
            )
            .addSampleRequest(
                id = "age_over_21_and_portrait",
                displayName = "Age Over 21 + Portrait",
                mdocDataElements = mapOf(
                    MDL_NAMESPACE to mapOf(
                        "age_over_21" to false,
                        "portrait" to false
                    )
                ),
            )
            .addSampleRequest(
                id = "mandatory",
                displayName = "Mandatory Data Elements",
                mdocDataElements = mapOf(
                    MDL_NAMESPACE to mapOf(
                        "family_name" to false,
                        "given_name" to false,
                        "birth_date" to false,
                        "issue_date" to false,
                        "expiry_date" to false,
                        "issuing_country" to false,
                        "issuing_authority" to false,
                        "document_number" to false,
                        "portrait" to false,
                        "driving_privileges" to false,
                        "un_distinguishing_sign" to false,
                    )
                )
            )
            .addSampleRequest(
                id = "full",
                displayName = "All Data Elements",
                mdocDataElements = mapOf(
                    MDL_NAMESPACE to mapOf(),
                    AAMVA_NAMESPACE to mapOf()
                )
            )
            .addSampleRequest(
                id = "name-and-address-partially-stored",
                displayName = "Name and Address (Partially Stored)",
                mdocDataElements = mapOf(
                    MDL_NAMESPACE to mapOf(
                        "family_name" to true,
                        "given_name" to true,
                        "issuing_authority" to false,
                        "portrait" to false,
                        "resident_address" to true,
                        "resident_city" to true,
                        "resident_state" to true,
                        "resident_postal_code" to true,
                        "resident_country" to true,
                    ),
                    AAMVA_NAMESPACE to mapOf(
                        "resident_county" to true,
                    )
                )
            )
            .addSampleRequest(
                id = "name-and-address-all-stored",
                displayName = "Name and Address (All Stored)",
                mdocDataElements = mapOf(
                    MDL_NAMESPACE to mapOf(
                        "family_name" to true,
                        "given_name" to true,
                        "issuing_authority" to true,
                        "portrait" to true,
                        "resident_address" to true,
                        "resident_city" to true,
                        "resident_state" to true,
                        "resident_postal_code" to true,
                        "resident_country" to true,
                    ),
                    AAMVA_NAMESPACE to mapOf(
                        "resident_county" to true,
                    )
                )
            )
            .build()
    }
}

