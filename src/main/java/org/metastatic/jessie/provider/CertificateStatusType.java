package org.metastatic.jessie.provider;

public enum CertificateStatusType {
    OCSP(1);

    public final int value;

    private CertificateStatusType(final int value) {
        this.value = value;
    }
}
