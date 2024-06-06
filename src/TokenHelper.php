<?php

// app/Helpers/LicenseHelper.php

namespace App\Helpers;

use Illuminate\Support\Facades\Crypt;

class TokenHelper
{
    public static function encryptLicenseData($startDate, $endDate, $secretKey)
    {
        // Combine as datas com a chave secreta
        $data = json_encode([
            'start_date' => $startDate,
            'end_date' => $endDate,
        ]);

        // Crie um checksum
        $checksum = hash_hmac('sha256', $data, $secretKey);

        // Combine os dados e o checksum
        $dataWithChecksum = $data . '|' . $checksum;

        // Criptografe os dados combinados
        return Crypt::encrypt($dataWithChecksum);
    }

    public static function decryptLicenseData($encryptedData, $secretKey)
    {
        // Descriptografe os dados
        $dataWithChecksum = Crypt::decrypt($encryptedData);

        // Separe os dados do checksum
        list($data, $checksum) = explode('|', $dataWithChecksum, 2);

        // Verifique o checksum
        $calculatedChecksum = hash_hmac('sha256', $data, $secretKey);
        if (!hash_equals($checksum, $calculatedChecksum)) {
            throw new \Exception('Checksum inválido');
        }

        // Retorne os dados originais
        return json_decode($data, true);
    }
}
